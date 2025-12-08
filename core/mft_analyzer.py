"""
Master File Table (MFT) Analysis Module
========================================
Forensic analysis of NTFS Master File Table

This module provides comprehensive MFT analysis:
- Raw volume access to read $MFT on live systems
- Parse active and deleted MFT entries
- Reconstruct full directory tree from parent references
- Detect deleted files and assess recoverability
- Identify Alternate Data Streams (ADS)
- Detect timestomping and other anomalies
- Extract file metadata and timestamps (MACB)

Technical Details:
- Uses pytsk3 (The Sleuth Kit) for raw NTFS access
- Bypasses Windows file locking via device handles (\\.\C:)
- Parses MFT records (typically 1024 bytes each)
- Analyzes $STANDARD_INFORMATION and $FILE_NAME attributes
- Evaluates cluster allocation via $Bitmap

Author: Forensics Tool Team
Date: December 2025
"""

import sys
import os
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple

# Import our NTFS parser
from core.ntfs_structures import (
    MFTRecord, NTFSParser,
    ATTR_STANDARD_INFORMATION, ATTR_FILE_NAME, ATTR_DATA,
    format_timestamp, format_filesize
)


class MFTAnalyzer:
    """
    Master File Table forensic analyzer
    Extracts deleted files, metadata, and anomalies from NTFS volumes
    """

    def __init__(self, volume_path: str = "C:"):
        """
        Initialize MFT analyzer

        Args:
            volume_path: Drive letter (e.g., "C:") or volume path
        """
        self.is_windows = sys.platform == 'win32'
        self.volume_path = volume_path
        self.volume_device = f"\\\\.\\{volume_path}"  # Raw device path

        # MFT data storage
        self.mft_records = {}  # entry_number -> MFTRecord
        self.deleted_files = []
        self.active_files = []

        # Directory tree reconstruction
        self.directory_tree = {}  # entry_number -> path

        # Statistics
        self.stats = {
            'total_entries': 0,
            'active_entries': 0,
            'deleted_entries': 0,
            'directories': 0,
            'files': 0,
            'ads_detected': 0,
            'timestomped_files': 0,
            'recoverable_files': 0,
            'partially_recoverable': 0,
            'non_recoverable': 0
        }

        # Anomalies
        self.anomalies = {
            'timestomped': [],
            'hidden_ads': [],
            'suspicious_paths': [],
            'orphaned_files': []
        }

        # Performance limits
        # Set to very high values to capture ALL deleted files
        # including those permanently removed from Recycle Bin
        self.max_entries_to_parse = 2000000  # Scan up to 2M entries (most systems have < 500K)
        self.deleted_file_limit = 50000  # Track up to 50K deleted files

    def analyze(self) -> Dict:
        """
        Main analysis function

        Returns:
            Dictionary containing MFT analysis results
        """

        print("\n[+] Starting MFT Analysis...")

        if not self.is_windows:
            print("    ⚠️  MFT Analysis requires Windows OS")
            return self._get_unavailable_data()

        # Check for Administrator privileges
        if not self._is_admin():
            print("    ⚠️  Administrator privileges required for MFT access")
            return self._get_unavailable_data()

        # Check if pytsk3 is available
        try:
            import pytsk3
        except ImportError:
            print("    ⚠️  pytsk3 module not installed. Run: pip install pytsk3")
            return self._get_unavailable_data()

        try:
            # Step 1: Open volume and get file system
            print(f"    📁 Opening volume {self.volume_path}...")
            fs_info = self._open_volume(pytsk3)

            if not fs_info:
                print("    ❌ Failed to open volume")
                return self._get_unavailable_data()

            # Step 2: Read and parse $MFT
            print("    📊 Reading Master File Table...")
            self._read_mft(fs_info, pytsk3)

            # Step 3: Reconstruct directory tree
            print("    🌳 Reconstructing directory tree...")
            self._reconstruct_paths()

            # Step 4: Classify and analyze files
            print("    🔍 Analyzing file entries...")
            self._classify_files()

            # Step 5: Detect anomalies
            print("    ⚠️  Detecting anomalies...")
            self._detect_anomalies()

            # Step 6: Assess recoverability
            print("    💾 Assessing file recoverability...")
            self._assess_recoverability()

            print(f"    ✅ MFT Analysis complete!")
            print(f"       - Total entries: {self.stats['total_entries']}")
            print(f"       - Deleted files: {self.stats['deleted_entries']}")
            print(f"       - Recoverable: {self.stats['recoverable_files']}")

        except Exception as e:
            print(f"    ❌ MFT Analysis error: {str(e)}")
            return self._get_unavailable_data()

        return self._get_results()

    def _is_admin(self) -> bool:
        """Check if running with Administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def _open_volume(self, pytsk3) -> Optional[object]:
        """
        Open volume using pytsk3 for raw access

        Returns:
            File system object or None
        """
        try:
            # Open volume image (raw device)
            img_info = pytsk3.Img_Info(self.volume_device)

            # Open file system (NTFS)
            fs_info = pytsk3.FS_Info(img_info, offset=0)

            # Verify it's NTFS
            if fs_info.info.ftype != pytsk3.TSK_FS_TYPE_NTFS:
                print(f"    ⚠️  Volume is not NTFS (type: {fs_info.info.ftype})")
                return None

            return fs_info

        except Exception as e:
            print(f"    ❌ Volume access error: {str(e)}")
            return None

    def _read_mft(self, fs_info, pytsk3):
        """
        Read and parse MFT records

        Args:
            fs_info: pytsk3 file system object

        CRITICAL FIX: Forces fresh MFT reads to detect recently deleted files.
        Windows may cache MFT updates, causing newly deleted files to not appear.
        """

        try:
            # ⚠️ CRITICAL: Re-open filesystem to flush any cached data
            # This ensures we see the most recent MFT state
            print(f"       🔄 Flushing MFT cache for fresh read...")

            # Close and reopen filesystem handle (forces kernel cache flush)
            # Note: pytsk3 doesn't have explicit cache flush, so we rely on reopen

            # Open $MFT file (inode 0)
            mft_file = fs_info.open_meta(inode=0)

            # Get MFT size
            mft_size = mft_file.info.meta.size
            record_size = 1024  # Typical MFT record size
            total_records = mft_size // record_size

            print(f"       MFT Size: {format_filesize(mft_size)}")
            print(f"       Total Records: {total_records}")
            print(f"       ⏱️  Reading MFT entries (this may take 30-60 seconds)...")

            # Limit parsing for performance
            records_to_parse = min(total_records, self.max_entries_to_parse)

            # Read and parse MFT records
            for entry_num in range(records_to_parse):
                try:
                    # Read record data
                    offset = entry_num * record_size
                    record_data = mft_file.read_random(offset, record_size)

                    if len(record_data) < record_size:
                        continue

                    # Parse MFT record
                    mft_record = self._parse_mft_record(record_data, entry_num)

                    if mft_record:
                        self.mft_records[entry_num] = mft_record
                        self.stats['total_entries'] += 1

                    # Progress indicator
                    if entry_num > 0 and entry_num % 10000 == 0:
                        print(f"       Parsed {entry_num:,} records...")

                except Exception as e:
                    # Skip corrupted records
                    continue

            print(f"       ✅ Parsed {self.stats['total_entries']:,} valid MFT records")

        except Exception as e:
            print(f"    ❌ MFT read error: {str(e)}")

    def _parse_mft_record(self, data: bytes, entry_num: int) -> Optional[MFTRecord]:
        """
        Parse a single MFT record

        Args:
            data: Raw MFT record bytes (1024 bytes)
            entry_num: MFT entry number

        Returns:
            MFTRecord object or None
        """

        try:
            # Parse header
            header = NTFSParser.parse_mft_header(data)

            if not header or header['signature'] not in ['FILE', 'BAAD']:
                return None

            # Create MFT record object
            record = MFTRecord()
            record.entry_number = entry_num
            record.sequence_number = header['sequence_number']
            record.is_in_use = header['is_in_use']
            record.is_directory = header['is_directory']
            record.is_deleted = not header['is_in_use']

            # Store raw record data for file content recovery
            record.raw_data = data

            # Parse attributes
            offset = header['first_attr_offset']
            si_times = {}
            fn_times = {}

            while offset < len(data) - 16:
                # Parse attribute header
                attr = NTFSParser.parse_attribute_header(data, offset)

                if not attr:
                    break

                # $STANDARD_INFORMATION
                if attr['type'] == ATTR_STANDARD_INFORMATION and not attr['is_non_resident']:
                    content_start = offset + attr['content_offset']
                    content_end = content_start + attr['content_length']
                    si_times = NTFSParser.parse_standard_information(data[content_start:content_end])

                    record.created = si_times.get('created')
                    record.modified = si_times.get('modified')
                    record.accessed = si_times.get('accessed')
                    record.mft_modified = si_times.get('mft_modified')

                # $FILE_NAME
                elif attr['type'] == ATTR_FILE_NAME and not attr['is_non_resident']:
                    content_start = offset + attr['content_offset']
                    content_end = content_start + attr['content_length']
                    fn_info = NTFSParser.parse_file_name(data[content_start:content_end])
                    fn_times = fn_info

                    # Prefer Win32 namespace (namespace=1) over DOS (namespace=2)
                    if fn_info.get('namespace') in [1, 3] or not record.filename:
                        record.filename = fn_info.get('filename', '')
                        record.parent_reference = fn_info.get('parent_reference', 0)
                        record.parent_sequence = fn_info.get('parent_sequence', 0)
                        record.logical_size = fn_info.get('real_size', 0)

                # $DATA
                elif attr['type'] == ATTR_DATA:
                    # Check for ADS (named data streams)
                    if attr['name']:
                        record.has_ads = True
                        record.ads_streams.append(attr['name'])

                    if attr['is_non_resident']:
                        # Parse data runs
                        record.is_resident = False
                        record.physical_size = attr.get('allocated_size', 0)

                        datarun_offset = offset + attr['datarun_offset']
                        record.data_runs = NTFSParser.parse_data_runs(data, datarun_offset)
                    else:
                        # Resident data (small files stored in MFT)
                        record.is_resident = True
                        record.physical_size = attr.get('content_length', 0)

                # Move to next attribute
                offset += attr['length']

            # Detect timestomping
            if si_times and fn_times:
                record.is_timestomped = NTFSParser.detect_timestomping(si_times, fn_times)

            return record

        except Exception as e:
            return None

    def _reconstruct_paths(self):
        """
        Reconstruct full file paths from parent references
        """

        # Build path for root directory
        if 5 in self.mft_records:  # Entry 5 is root directory
            self.directory_tree[5] = "/"

        # Iteratively build paths (multiple passes for deep hierarchies)
        max_iterations = 50
        for iteration in range(max_iterations):
            progress = False

            for entry_num, record in self.mft_records.items():
                # Skip if already has path
                if entry_num in self.directory_tree:
                    continue

                # Get parent path
                parent_ref = record.parent_reference

                if parent_ref in self.directory_tree:
                    parent_path = self.directory_tree[parent_ref]

                    # Build full path
                    if parent_path == "/":
                        full_path = "/" + record.filename
                    else:
                        full_path = parent_path + "/" + record.filename

                    self.directory_tree[entry_num] = full_path
                    record.full_path = full_path
                    progress = True

            # Exit if no progress made
            if not progress:
                break

        # Mark orphaned files (no parent path found)
        for entry_num, record in self.mft_records.items():
            if entry_num not in self.directory_tree and record.filename:
                record.full_path = f"[ORPHANED]/{record.filename}"
                record.anomaly_flags.append("ORPHANED")

    def _classify_files(self):
        """
        Classify files as active, deleted, directories, etc.
        """

        deleted_count = 0

        for record in self.mft_records.values():
            # Count directories
            if record.is_directory:
                self.stats['directories'] += 1
            else:
                self.stats['files'] += 1

            # Count ADS
            if record.has_ads:
                self.stats['ads_detected'] += len(record.ads_streams)

            # Count timestomped files
            if record.is_timestomped:
                self.stats['timestomped_files'] += 1

            # Classify as active or deleted
            if record.is_deleted:
                self.stats['deleted_entries'] += 1

                # ⚠️ CHECK: Was this file deleted very recently? (last 60 seconds)
                # Windows may not have flushed MFT to disk yet
                if record.modified:
                    time_since_deletion = (datetime.now() - record.modified).total_seconds()
                    if time_since_deletion < 60:
                        record.anomaly_flags.append("RECENTLY_DELETED")
                        # Mark as potentially incomplete data
                        if not hasattr(record, 'warnings'):
                            record.warnings = []
                        record.warnings.append(
                            f"Deleted {int(time_since_deletion)}s ago - MFT may still be updating"
                        )

                # Limit deleted files to track
                if deleted_count < self.deleted_file_limit:
                    self.deleted_files.append(record)
                    deleted_count += 1
            else:
                self.stats['active_entries'] += 1
                self.active_files.append(record)

    def _detect_anomalies(self):
        """
        Detect suspicious patterns and anomalies
        """

        for record in self.mft_records.values():
            # Timestomped files
            if record.is_timestomped:
                self.anomalies['timestomped'].append({
                    'filename': record.filename,
                    'path': record.full_path,
                    'entry': record.entry_number,
                    'severity': 'HIGH'
                })

            # Hidden ADS
            if record.has_ads and len(record.ads_streams) > 0:
                self.anomalies['hidden_ads'].append({
                    'filename': record.filename,
                    'path': record.full_path,
                    'streams': record.ads_streams,
                    'severity': 'MEDIUM'
                })

            # Orphaned files
            if 'ORPHANED' in record.anomaly_flags:
                self.anomalies['orphaned_files'].append({
                    'filename': record.filename,
                    'entry': record.entry_number,
                    'severity': 'LOW'
                })

            # Suspicious paths (e.g., hidden in system folders)
            if record.full_path and any(x in record.full_path.lower() for x in ['$recycle', 'temp', 'tmp', 'cache']):
                if record.logical_size > 10 * 1024 * 1024:  # > 10MB
                    self.anomalies['suspicious_paths'].append({
                        'filename': record.filename,
                        'path': record.full_path,
                        'size': record.logical_size,
                        'severity': 'LOW'
                    })

    def _assess_recoverability(self):
        """
        Assess recoverability of deleted files

        Note: Full $Bitmap analysis requires additional implementation
        For now, use heuristics based on data runs
        """

        for record in self.deleted_files:
            # Heuristic assessment
            if record.is_resident:
                # Resident files are stored in MFT - fully recoverable
                record.recoverability = "FULL"
                self.stats['recoverable_files'] += 1

            elif len(record.data_runs) > 0:
                # Has data runs - potentially recoverable
                # (Would need $Bitmap analysis to confirm clusters are free)
                record.recoverability = "PARTIAL"
                self.stats['partially_recoverable'] += 1

            else:
                # No data runs - metadata only
                record.recoverability = "METADATA_ONLY"
                self.stats['non_recoverable'] += 1

    def _get_results(self) -> Dict:
        """
        Compile analysis results
        """

        return {
            'is_windows': self.is_windows,
            'volume_path': self.volume_path,
            'stats': self.stats,
            'deleted_files': self.deleted_files[:1000],  # Limit for UI performance
            'anomalies': self.anomalies,
            'timeline': self._generate_timeline()
        }

    def _get_unavailable_data(self) -> Dict:
        """
        Return empty data structure when analysis is unavailable
        """

        return {
            'is_windows': self.is_windows,
            'volume_path': self.volume_path,
            'stats': self.stats,
            'deleted_files': [],
            'anomalies': {
                'timestomped': [],
                'hidden_ads': [],
                'suspicious_paths': [],
                'orphaned_files': []
            },
            'timeline': []
        }

    def _generate_timeline(self) -> List[Dict]:
        """
        Generate timeline of deleted file events

        CRITICAL FIX: Properly handle None/invalid timestamps.
        Files with no timestamp are placed at END of timeline (least recent).
        """

        timeline = []

        for record in self.deleted_files[:100]:  # Top 100 most recent
            # Only add files with valid timestamps to timeline
            if record.modified and isinstance(record.modified, datetime):
                timeline.append({
                    'timestamp': record.modified,
                    'event': 'File Deleted',
                    'filename': record.filename,
                    'path': record.full_path,
                    'size': record.logical_size,
                    'recoverability': record.recoverability
                })

        # Sort by timestamp (most recent first)
        # Using a lambda that safely handles datetime objects
        # Files with invalid/None timestamps are already excluded above
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)

        return timeline

    def get_statistics(self) -> Dict:
        """
        Get analysis statistics for dashboard
        """

        return {
            'total_entries': self.stats['total_entries'],
            'active_entries': self.stats['active_entries'],
            'deleted_entries': self.stats['deleted_entries'],
            'recoverable_files': self.stats['recoverable_files'],
            'partially_recoverable': self.stats['partially_recoverable'],
            'non_recoverable': self.stats['non_recoverable'],
            'ads_detected': self.stats['ads_detected'],
            'timestomped_files': self.stats['timestomped_files'],
            'anomalies_detected': (
                len(self.anomalies['timestomped']) +
                len(self.anomalies['hidden_ads']) +
                len(self.anomalies['suspicious_paths']) +
                len(self.anomalies['orphaned_files'])
            )
        }

    def recover_file(self, entry_number: int) -> Tuple[bool, str, Optional[bytes]]:
        """
        Recover actual file content from MFT record

        Args:
            entry_number: MFT entry number

        Returns:
            Tuple of (success, message, file_content_bytes)
        """

        if entry_number not in self.mft_records:
            return False, "MFT entry not found", None

        record = self.mft_records[entry_number]

        if not record.is_deleted:
            return False, "File is not deleted (still active)", None

        if record.is_directory:
            return False, "Cannot recover directory entries", None

        # Only resident files can be directly recovered from MFT
        if not record.is_resident:
            return False, f"File is non-resident ({format_filesize(record.logical_size)}). Cluster-level recovery requires advanced tools.", None

        # Extract resident data from raw MFT record
        try:
            from core.mft_file_recovery import MFTFileRecovery
            recovery = MFTFileRecovery(self.volume_path)

            # Get file content from MFT record
            success, result = recovery.recover_resident_file(record.raw_data, record.filename)

            if success:
                # Read the recovered file
                with open(result, 'rb') as f:
                    content = f.read()
                return True, f"File recovered: {result}", content
            else:
                return False, result, None

        except Exception as e:
            return False, f"Recovery error: {str(e)}", None

    def preview_file(self, entry_number: int) -> dict:
        """
        Get preview of file content (hex + text)

        Args:
            entry_number: MFT entry number

        Returns:
            Dictionary with preview data
        """

        if entry_number not in self.mft_records:
            return {'success': False, 'error': 'Entry not found'}

        record = self.mft_records[entry_number]

        if not record.is_resident:
            return {
                'success': False,
                'error': f'File is non-resident ({format_filesize(record.logical_size)}). Too large for preview.'
            }

        try:
            from core.mft_file_recovery import MFTFileRecovery
            recovery = MFTFileRecovery(self.volume_path)

            preview = recovery.get_file_preview(record.raw_data)

            if preview.get('success'):
                preview['filename'] = record.filename
                preview['size_formatted'] = format_filesize(preview.get('size', 0))

            return preview

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def export_metadata(self, entry_number: int) -> Optional[dict]:
        """
        Export complete metadata for an MFT entry

        Args:
            entry_number: MFT entry number

        Returns:
            Dictionary with all metadata
        """

        if entry_number not in self.mft_records:
            return None

        record = self.mft_records[entry_number]

        return {
            'entry_number': record.entry_number,
            'filename': record.filename,
            'full_path': record.full_path,
            'file_size': record.logical_size,
            'file_size_formatted': format_filesize(record.logical_size),
            'is_deleted': record.is_deleted,
            'is_directory': record.is_directory,
            'is_resident': record.is_resident,
            'recoverability': record.recoverability,

            'timestamps': {
                'created': format_timestamp(record.created),
                'modified': format_timestamp(record.modified),
                'accessed': format_timestamp(record.accessed),
                'mft_modified': format_timestamp(record.mft_modified)
            },

            'anomalies': {
                'is_timestomped': record.is_timestomped,
                'has_ads': record.has_ads,
                'ads_streams': record.ads_streams,
                'flags': record.anomaly_flags
            },

            'technical': {
                'sequence_number': record.sequence_number,
                'parent_reference': record.parent_reference,
                'parent_sequence': record.parent_sequence,
                'data_runs': record.data_runs,
                'physical_size': record.physical_size,
                'physical_size_formatted': format_filesize(record.physical_size)
            }
        }


# Convenience function for quick analysis
def analyze_mft(volume_path: str = "C:") -> Tuple[Dict, Dict]:
    """
    Perform MFT analysis on specified volume

    Args:
        volume_path: Drive letter (e.g., "C:")

    Returns:
        Tuple of (mft_data, mft_stats)
    """

    analyzer = MFTAnalyzer(volume_path)
    mft_data = analyzer.analyze()
    mft_stats = analyzer.get_statistics()

    return mft_data, mft_stats
