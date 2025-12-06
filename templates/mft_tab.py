"""
MFT Analysis Tab Generator
===========================
Generates HTML for NTFS Master File Table (MFT) analysis tab

Displays:
- Summary statistics (total entries, deleted files, recoverable)
- Deleted files table with recovery status
- File timeline visualization
- Anomaly detection (timestomping, ADS, orphaned files)
- Recovery recommendations

Author: Forensics Tool Team
Date: December 2025
"""

from core.ntfs_structures import format_timestamp, format_filesize
from core.file_recovery import get_recovery_badge_color, get_recovery_icon


def generate_mft_tab(mft_data, mft_stats):
    """
    Generate MFT Analysis tab

    Args:
        mft_data: Dictionary containing MFT analysis data
        mft_stats: Statistics about MFT analysis

    Returns:
        HTML string for MFT analysis tab
    """

    total_entries = mft_stats.get('total_entries', 0)
    active_entries = mft_stats.get('active_entries', 0)
    deleted_entries = mft_stats.get('deleted_entries', 0)
    recoverable_files = mft_stats.get('recoverable_files', 0)
    partially_recoverable = mft_stats.get('partially_recoverable', 0)
    non_recoverable = mft_stats.get('non_recoverable', 0)
    ads_detected = mft_stats.get('ads_detected', 0)
    timestomped_files = mft_stats.get('timestomped_files', 0)
    anomalies_detected = mft_stats.get('anomalies_detected', 0)

    is_windows = mft_data.get('is_windows', False)
    volume_path = mft_data.get('volume_path', 'C:')

    deleted_files = mft_data.get('deleted_files', [])
    anomalies = mft_data.get('anomalies', {})
    timeline = mft_data.get('timeline', [])

    html = f'''
    <div id="tab-mft" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>💾 MFT Analysis - Deleted Files & Recovery</h1>
                <p>NTFS Master File Table forensic analysis and file recovery assessment</p>
            </div>
        </div>
    '''

    # If not Windows, show informational message
    if not is_windows:
        html += '''
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px; padding: 24px; margin: 20px 0;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 48px;">ℹ️</div>
                <div>
                    <h3 style="margin: 0 0 8px 0; color: #3b82f6;">MFT Analysis Unavailable</h3>
                    <p style="margin: 0; color: #9ca3af; line-height: 1.6;">
                        Master File Table (MFT) analysis requires running on a Windows system with Administrator privileges.
                        <br>This feature parses NTFS metadata to recover deleted files and assess recoverability.
                    </p>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <strong style="color: #60a5fa;">Required Components:</strong><br>
                        • Windows Operating System with NTFS volume<br>
                        • Administrator/Elevated privileges<br>
                        • pytsk3 module installed: <code>pip install pytsk3</code><br>
                        • Raw volume access permission (\\.\C:)
                    </div>
                </div>
            </div>
        </div>
        '''

    elif total_entries == 0:
        # Analysis failed or no permission
        html += '''
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                    border-radius: 12px; padding: 24px; margin: 20px 0;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 48px;">⚠️</div>
                <div>
                    <h3 style="margin: 0 0 8px 0; color: #ef4444;">MFT Analysis Failed</h3>
                    <p style="margin: 0; color: #9ca3af; line-height: 1.6;">
                        Unable to access the Master File Table. This typically occurs due to insufficient permissions
                        or missing dependencies.
                    </p>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <strong style="color: #f87171;">Troubleshooting Steps:</strong><br>
                        1. Verify you're running as Administrator<br>
                        2. Install pytsk3: <code>pip install pytsk3</code><br>
                        3. Check volume path is valid (e.g., C:)<br>
                        4. Ensure volume is NTFS filesystem<br>
                        5. Disable antivirus temporarily if blocking access
                    </div>
                </div>
            </div>
        </div>
        '''

    else:
        # Summary Stats Grid
        html += f'''
        <div class="hash-stats-grid">
            <div class="hash-stat-card">
                <div class="stat-number">{total_entries:,}</div>
                <div class="stat-label">MFT Entries</div>
                <div class="stat-sublabel">Total records parsed</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number" style="color: #ef4444;">{deleted_entries:,}</div>
                <div class="stat-label">Deleted Files</div>
                <div class="stat-sublabel">File records marked deleted</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number" style="color: #10b981;">{recoverable_files:,}</div>
                <div class="stat-label">Fully Recoverable</div>
                <div class="stat-sublabel">100% recovery possible</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number" style="color: #f59e0b;">{partially_recoverable:,}</div>
                <div class="stat-label">Partially Recoverable</div>
                <div class="stat-sublabel">Some data remains</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number" style="color: {'#ef4444' if anomalies_detected > 0 else '#6b7280'};">{anomalies_detected}</div>
                <div class="stat-label">Anomalies</div>
                <div class="stat-sublabel">Suspicious patterns</div>
            </div>
        </div>
        '''

        # Anomalies Section (HIGH PRIORITY)
        if anomalies_detected > 0:
            html += generate_mft_anomalies_section(anomalies)

        # Deleted Files Table
        if len(deleted_files) > 0:
            html += generate_deleted_files_table(deleted_files)
        else:
            html += '''
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3);
                        border-radius: 12px; padding: 24px; margin: 20px 0; text-align: center;">
                <div style="font-size: 48px;">✅</div>
                <h3 style="margin: 10px 0; color: #10b981;">No Deleted Files Found</h3>
                <p style="color: #9ca3af; margin: 0;">
                    No deleted file records detected in MFT analysis. Volume appears clean.
                </p>
            </div>
            '''

        # Timeline Section
        if len(timeline) > 0:
            html += generate_mft_timeline_section(timeline)

        # Additional Statistics
        html += f'''
        <div class="command-cards" style="margin-top: 24px;">
            <div class="command-card">
                <div class="command-card-header" onclick="toggleCommandOutput(this)">
                    <div class="command-title">
                        <span class="cmd-type-badge" style="background: rgba(59, 130, 246, 0.2); color: #3b82f6;">📊 STATISTICS</span>
                        <span>Additional MFT Metrics</span>
                    </div>
                    <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div class="command-card-body">
                    <div class="command-output">
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                            <div style="padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                                <div style="color: #9ca3af; font-size: 0.85rem; margin-bottom: 4px;">Active Files</div>
                                <div style="font-size: 1.5rem; font-weight: 600; color: #10b981;">{active_entries:,}</div>
                            </div>
                            <div style="padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                                <div style="color: #9ca3af; font-size: 0.85rem; margin-bottom: 4px;">Deleted Files</div>
                                <div style="font-size: 1.5rem; font-weight: 600; color: #ef4444;">{deleted_entries:,}</div>
                            </div>
                            <div style="padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                                <div style="color: #9ca3af; font-size: 0.85rem; margin-bottom: 4px;">ADS Streams Detected</div>
                                <div style="font-size: 1.5rem; font-weight: 600; color: #f59e0b;">{ads_detected:,}</div>
                            </div>
                            <div style="padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                                <div style="color: #9ca3af; font-size: 0.85rem; margin-bottom: 4px;">Timestomped Files</div>
                                <div style="font-size: 1.5rem; font-weight: 600; color: #ef4444;">{timestomped_files:,}</div>
                            </div>
                        </div>
                        <div style="margin-top: 16px; padding: 16px; background: rgba(59, 130, 246, 0.1); border-radius: 8px; border-left: 4px solid #3b82f6;">
                            <strong style="color: #3b82f6;">💡 Analysis Notes:</strong><br>
                            • Volume analyzed: <strong>{volume_path}</strong><br>
                            • Parsed <strong>{total_entries:,}</strong> MFT entries<br>
                            • Recovery assessment based on cluster allocation status<br>
                            • Timestomping detected by comparing $SI and $FN attributes
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''

    html += '''
    </div>
    '''

    return html


def generate_mft_anomalies_section(anomalies):
    """
    Generate anomalies section HTML
    """

    html = '''
    <div class="command-cards">
        <div class="command-card" style="border: 2px solid rgba(239, 68, 68, 0.5);">
            <div class="command-card-header" onclick="toggleCommandOutput(this)" style="background: rgba(239, 68, 68, 0.1);">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444;">⚠️ ANOMALIES</span>
                    <span>Suspicious MFT Patterns Detected</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body" style="display: block;">
                <div class="command-output">
    '''

    # Timestomped Files
    if anomalies.get('timestomped') and len(anomalies['timestomped']) > 0:
        timestomped = anomalies['timestomped']
        html += f'''
                    <div style="margin-bottom: 24px;">
                        <h3 style="color: #ef4444; margin-bottom: 12px;">
                            🔴 Timestomped Files ({len(timestomped)})
                        </h3>
                        <p style="color: #9ca3af; margin-bottom: 12px; font-size: 0.9rem;">
                            Files with modified timestamps that don't match MFT records (anti-forensics technique)
                        </p>
                        <table class="data-table" style="width: 100%;">
                            <thead>
                                <tr>
                                    <th style="width: 30%;">Filename</th>
                                    <th style="width: 50%;">Path</th>
                                    <th style="width: 20%;">Severity</th>
                                </tr>
                            </thead>
                            <tbody>
        '''

        for anomaly in timestomped[:20]:  # Show top 20
            filename = anomaly.get('filename', 'Unknown')
            path = anomaly.get('path', 'Unknown')
            severity = anomaly.get('severity', 'MEDIUM')

            severity_badge = 'badge-red' if severity == 'HIGH' else 'badge-orange'

            html += f'''
                                <tr>
                                    <td><strong>{filename}</strong></td>
                                    <td><span style="font-size: 0.85rem; font-family: monospace;">{path}</span></td>
                                    <td><span class="badge {severity_badge}">{severity}</span></td>
                                </tr>
            '''

        html += '''
                            </tbody>
                        </table>
                    </div>
        '''

    # Hidden ADS
    if anomalies.get('hidden_ads') and len(anomalies['hidden_ads']) > 0:
        hidden_ads = anomalies['hidden_ads']
        html += f'''
                    <div style="margin-bottom: 24px;">
                        <h3 style="color: #f59e0b; margin-bottom: 12px;">
                            🟡 Alternate Data Streams (ADS) Detected ({len(hidden_ads)})
                        </h3>
                        <p style="color: #9ca3af; margin-bottom: 12px; font-size: 0.9rem;">
                            Files with hidden alternate data streams (can be used to hide malicious content)
                        </p>
                        <table class="data-table" style="width: 100%;">
                            <thead>
                                <tr>
                                    <th style="width: 30%;">Filename</th>
                                    <th style="width: 40%;">Path</th>
                                    <th style="width: 30%;">ADS Streams</th>
                                </tr>
                            </thead>
                            <tbody>
        '''

        for anomaly in hidden_ads[:20]:
            filename = anomaly.get('filename', 'Unknown')
            path = anomaly.get('path', 'Unknown')
            streams = anomaly.get('streams', [])
            streams_str = ', '.join(streams) if streams else 'Unknown'

            html += f'''
                                <tr>
                                    <td><strong>{filename}</strong></td>
                                    <td><span style="font-size: 0.85rem; font-family: monospace;">{path}</span></td>
                                    <td><span class="badge badge-orange">{streams_str}</span></td>
                                </tr>
            '''

        html += '''
                            </tbody>
                        </table>
                    </div>
        '''

    # Orphaned Files
    if anomalies.get('orphaned_files') and len(anomalies['orphaned_files']) > 0:
        orphaned = anomalies['orphaned_files']
        html += f'''
                    <div style="margin-bottom: 24px;">
                        <h3 style="color: #6b7280; margin-bottom: 12px;">
                            ⚪ Orphaned Files ({len(orphaned)})
                        </h3>
                        <p style="color: #9ca3af; margin-bottom: 12px; font-size: 0.9rem;">
                            Files without valid parent directory references (corrupted or partially deleted)
                        </p>
                        <div style="color: #9ca3af; font-size: 0.9rem;">
                            Found {len(orphaned)} orphaned file entries (likely from filesystem corruption or incomplete deletion)
                        </div>
                    </div>
        '''

    html += '''
                </div>
            </div>
        </div>
    </div>
    '''

    return html


def generate_deleted_files_table(deleted_files):
    """
    Generate deleted files table HTML
    """

    html = f'''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444;">🗑️ DELETED FILES</span>
                    <span>Recovered Deleted File Records ({len(deleted_files)} shown)</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body" style="display: block;">
                <div class="command-output">
                    <table class="data-table" style="width: 100%;">
                        <thead>
                            <tr>
                                <th style="width: 20%;">Filename</th>
                                <th style="width: 30%;">Path</th>
                                <th style="width: 10%;">Size</th>
                                <th style="width: 15%;">Modified Date</th>
                                <th style="width: 15%;">Recoverability</th>
                                <th style="width: 10%;">Entry #</th>
                            </tr>
                        </thead>
                        <tbody>
    '''

    for record in deleted_files[:500]:  # Limit to 500 for performance
        filename = record.filename or '[No Name]'
        path = record.full_path or '[Unknown]'
        size = format_filesize(record.logical_size)
        modified = format_timestamp(record.modified)
        recoverability = record.recoverability
        entry_num = record.entry_number

        recovery_badge = get_recovery_badge_color(recoverability)
        recovery_icon = get_recovery_icon(recoverability)

        html += f'''
                            <tr>
                                <td><strong>{filename}</strong></td>
                                <td><span style="font-size: 0.8rem; font-family: monospace;">{path}</span></td>
                                <td>{size}</td>
                                <td><span style="font-size: 0.8rem;">{modified}</span></td>
                                <td><span class="badge {recovery_badge}">{recovery_icon} {recoverability}</span></td>
                                <td><span style="font-size: 0.8rem; color: #6b7280;">#{entry_num}</span></td>
                            </tr>
        '''

    html += '''
                        </tbody>
                    </table>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(59, 130, 246, 0.1); border-radius: 8px; border-left: 4px solid #3b82f6;">
                        <strong style="color: #3b82f6;">🔍 Recovery Legend:</strong><br>
                        • <span class="badge badge-green">✅ FULL</span> - All data clusters free, 100% recoverable<br>
                        • <span class="badge badge-orange">⚠️ PARTIAL</span> - Some clusters overwritten, partial recovery possible<br>
                        • <span class="badge badge-gray">📋 METADATA_ONLY</span> - Only file metadata available<br>
                        <br>
                        <strong>Recommended Recovery Tools:</strong> PhotoRec, TestDisk, Recuva, Autopsy, FTK Imager
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''

    return html


def generate_mft_timeline_section(timeline):
    """
    Generate timeline section HTML
    """

    html = f'''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(139, 92, 246, 0.2); color: #8b5cf6;">📅 TIMELINE</span>
                    <span>File Deletion Timeline ({len(timeline)} events)</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
    '''

    for event in timeline[:50]:  # Show top 50 events
        timestamp = format_timestamp(event.get('timestamp'))
        filename = event.get('filename', 'Unknown')
        path = event.get('path', 'Unknown')
        size = format_filesize(event.get('size', 0))
        recoverability = event.get('recoverability', 'UNKNOWN')
        recovery_badge = get_recovery_badge_color(recoverability)

        html += f'''
                    <div style="padding: 12px; background: rgba(0,0,0,0.2); border-left: 3px solid #8b5cf6; margin-bottom: 8px; border-radius: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1;">
                                <div style="font-weight: 600; color: #ffffff; margin-bottom: 4px;">
                                    {filename}
                                </div>
                                <div style="font-size: 0.85rem; color: #9ca3af; font-family: monospace;">
                                    {path}
                                </div>
                            </div>
                            <div style="text-align: right; margin-left: 16px;">
                                <div style="font-size: 0.8rem; color: #6b7280; margin-bottom: 4px;">
                                    {timestamp}
                                </div>
                                <div>
                                    <span class="badge badge-gray">{size}</span>
                                    <span class="badge {recovery_badge}">{recoverability}</span>
                                </div>
                            </div>
                        </div>
                    </div>
        '''

    html += '''
                </div>
            </div>
        </div>
    </div>
    '''

    return html
