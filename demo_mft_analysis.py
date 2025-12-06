"""
MFT Analysis Demo - Mock Data Simulator
========================================
Simulates MFT analysis with realistic mock data for testing UI on non-Windows systems

This demo generates:
- Realistic MFT records with deleted files
- Timestomped files (anti-forensics)
- Alternate Data Streams (ADS)
- Recovery assessment data
- Timeline events
- Anomalies

Run this to see the MFT Analysis tab without needing Windows or pytsk3!

Usage:
    python demo_mft_analysis.py
"""

import os
import sys
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from templates.mft_tab import generate_mft_tab
from templates.html_generator import generate_html_header, generate_html_footer


def generate_mock_mft_data():
    """
    Generate realistic mock MFT analysis data
    """

    print("🔄 Generating mock MFT data...")

    # Create realistic deleted files
    deleted_files = []

    # Category 1: User documents (recoverable)
    document_names = [
        "Financial_Report_2024.xlsx",
        "Project_Proposal.docx",
        "Client_Database.csv",
        "Meeting_Notes.txt",
        "Budget_Analysis.pdf",
        "Employee_Records.xlsx",
        "Confidential_Memo.docx",
        "Sales_Data_Q4.csv",
        "Marketing_Strategy.pptx",
        "Legal_Contract.pdf"
    ]

    # Category 2: Suspicious files (timestomped, partial recovery)
    suspicious_names = [
        "passwords.txt",
        "company_secrets.zip",
        "leaked_data.csv",
        "hack_tools.exe",
        "keylogger.dll",
        "backdoor.exe",
        "stolen_credentials.txt",
        "exploit_kit.zip"
    ]

    # Category 3: System files (non-recoverable)
    system_names = [
        "temp_cache.tmp",
        "log_file.log",
        "swap_data.bin",
        "thumbnail_cache.db",
        "browser_cache.dat"
    ]

    entry_counter = 1000

    # Generate recoverable documents
    for i, filename in enumerate(document_names):
        days_ago = random.randint(1, 180)
        modified_time = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))

        file_record = type('obj', (object,), {
            'entry_number': entry_counter,
            'filename': filename,
            'full_path': f"/Users/John.Doe/Documents/{filename}",
            'logical_size': random.randint(50000, 5000000),  # 50KB to 5MB
            'modified': modified_time,
            'created': modified_time - timedelta(days=random.randint(1, 30)),
            'accessed': modified_time + timedelta(hours=random.randint(1, 48)),
            'mft_modified': modified_time,
            'is_resident': random.choice([True, False]),
            'is_deleted': True,
            'is_directory': False,
            'has_ads': False,
            'ads_streams': [],
            'is_timestomped': False,
            'recoverability': 'FULL',
            'data_runs': [(5000 + i * 100, 10)] if not random.choice([True, False]) else []
        })()

        deleted_files.append(file_record)
        entry_counter += 1

    # Generate suspicious files (timestomped, partial recovery)
    for i, filename in enumerate(suspicious_names):
        days_ago = random.randint(1, 90)
        modified_time = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))

        # Some files have ADS
        has_ads = random.choice([True, False])
        ads_streams = [':Zone.Identifier', ':hidden_data'] if has_ads else []

        file_record = type('obj', (object,), {
            'entry_number': entry_counter,
            'filename': filename,
            'full_path': f"/Users/John.Doe/Desktop/suspicious/{filename}",
            'logical_size': random.randint(1000, 500000),  # 1KB to 500KB
            'modified': modified_time,
            'created': modified_time - timedelta(days=random.randint(1, 5)),
            'accessed': modified_time + timedelta(hours=random.randint(1, 12)),
            'mft_modified': modified_time,
            'is_resident': False,
            'is_deleted': True,
            'is_directory': False,
            'has_ads': has_ads,
            'ads_streams': ads_streams,
            'is_timestomped': True,  # Suspicious!
            'recoverability': random.choice(['PARTIAL', 'METADATA_ONLY']),
            'data_runs': [(10000 + i * 50, 5)]
        })()

        deleted_files.append(file_record)
        entry_counter += 1

    # Generate system files (non-recoverable)
    for i, filename in enumerate(system_names):
        days_ago = random.randint(1, 7)
        modified_time = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))

        file_record = type('obj', (object,), {
            'entry_number': entry_counter,
            'filename': filename,
            'full_path': f"/Windows/Temp/{filename}",
            'logical_size': random.randint(1024, 100000),  # 1KB to 100KB
            'modified': modified_time,
            'created': modified_time - timedelta(hours=random.randint(1, 48)),
            'accessed': modified_time,
            'mft_modified': modified_time,
            'is_resident': True,
            'is_deleted': True,
            'is_directory': False,
            'has_ads': False,
            'ads_streams': [],
            'is_timestomped': False,
            'recoverability': 'METADATA_ONLY',
            'data_runs': []
        })()

        deleted_files.append(file_record)
        entry_counter += 1

    # Generate anomalies
    anomalies = {
        'timestomped': [],
        'hidden_ads': [],
        'suspicious_paths': [],
        'orphaned_files': []
    }

    # Add timestomped files to anomalies
    for file_record in deleted_files:
        if file_record.is_timestomped:
            anomalies['timestomped'].append({
                'filename': file_record.filename,
                'path': file_record.full_path,
                'entry': file_record.entry_number,
                'severity': 'HIGH'
            })

        if file_record.has_ads:
            anomalies['hidden_ads'].append({
                'filename': file_record.filename,
                'path': file_record.full_path,
                'streams': file_record.ads_streams,
                'severity': 'MEDIUM'
            })

    # Add some suspicious paths
    anomalies['suspicious_paths'].append({
        'filename': 'large_temp_file.bin',
        'path': '/Windows/Temp/large_temp_file.bin',
        'size': 52428800,  # 50MB
        'severity': 'LOW'
    })

    # Add orphaned files
    anomalies['orphaned_files'].append({
        'filename': 'corrupted_entry.dat',
        'entry': 99999,
        'severity': 'LOW'
    })

    # Generate timeline
    timeline = []
    for file_record in sorted(deleted_files, key=lambda x: x.modified if x.modified else datetime.min, reverse=True)[:20]:
        if file_record.modified:
            timeline.append({
                'timestamp': file_record.modified,
                'event': 'File Deleted',
                'filename': file_record.filename,
                'path': file_record.full_path,
                'size': file_record.logical_size,
                'recoverability': file_record.recoverability
            })

    # Create final data structure
    mft_data = {
        'is_windows': False,  # We're simulating
        'volume_path': 'C: (SIMULATED)',
        'deleted_files': deleted_files,
        'anomalies': anomalies,
        'timeline': timeline
    }

    # Calculate statistics
    mft_stats = {
        'total_entries': 150000,  # Simulated total
        'active_entries': 150000 - len(deleted_files),
        'deleted_entries': len(deleted_files),
        'recoverable_files': len([f for f in deleted_files if f.recoverability == 'FULL']),
        'partially_recoverable': len([f for f in deleted_files if f.recoverability == 'PARTIAL']),
        'non_recoverable': len([f for f in deleted_files if f.recoverability == 'METADATA_ONLY']),
        'ads_detected': sum(len(f.ads_streams) for f in deleted_files),
        'timestomped_files': len([f for f in deleted_files if f.is_timestomped]),
        'anomalies_detected': (
            len(anomalies['timestomped']) +
            len(anomalies['hidden_ads']) +
            len(anomalies['suspicious_paths']) +
            len(anomalies['orphaned_files'])
        )
    }

    print(f"✅ Generated {len(deleted_files)} mock deleted files")
    print(f"   - Recoverable: {mft_stats['recoverable_files']}")
    print(f"   - Partial: {mft_stats['partially_recoverable']}")
    print(f"   - Non-recoverable: {mft_stats['non_recoverable']}")
    print(f"   - Timestomped: {mft_stats['timestomped_files']}")
    print(f"   - ADS detected: {mft_stats['ads_detected']}")
    print(f"   - Total anomalies: {mft_stats['anomalies_detected']}")

    return mft_data, mft_stats


def generate_demo_report():
    """
    Generate a complete HTML report with mock MFT data
    """

    print("\n" + "="*70)
    print("🎬 MFT ANALYSIS DEMO - GENERATING MOCK DATA REPORT")
    print("="*70)

    # Generate mock data
    mft_data, mft_stats = generate_mock_mft_data()

    # Update to show simulation notice
    mft_data['is_windows'] = True  # Show the actual UI
    mft_stats['total_entries'] = 150000  # Realistic number

    # Create demo report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    demo_file = f"demo_mft_report_{timestamp}.html"

    print(f"\n📝 Generating HTML report: {demo_file}")

    with open(demo_file, "w", encoding="utf-8") as f:
        # Write HTML header
        f.write(generate_html_header(timestamp, ""))

        # Add simulation notice banner
        f.write('''
        <style>
            .demo-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 16px;
                text-align: center;
                font-size: 1.1rem;
                font-weight: 600;
                z-index: 10000;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                animation: slideDown 0.5s ease-out;
            }

            @keyframes slideDown {
                from {
                    transform: translateY(-100%);
                }
                to {
                    transform: translateY(0);
                }
            }

            .demo-banner span {
                background: rgba(255,255,255,0.2);
                padding: 4px 12px;
                border-radius: 20px;
                margin-left: 12px;
                font-size: 0.9rem;
            }

            .app-container {
                margin-top: 60px !important;
            }
        </style>
        <div class="demo-banner">
            🎬 DEMO MODE - Mock MFT Data for UI Preview
            <span>No Windows Required</span>
            <span>pytsk3 Not Needed</span>
        </div>
        ''')

        # Generate MFT tab content
        f.write('<div style="margin-top: 60px;">')
        mft_tab_html = generate_mft_tab(mft_data, mft_stats)
        f.write(mft_tab_html)
        f.write('</div>')

        # Write footer
        f.write(generate_html_footer())

    print(f"✅ Demo report generated: {demo_file}")
    print(f"\n{'='*70}")
    print(f"📊 DEMO STATISTICS:")
    print(f"   Total MFT Entries: {mft_stats['total_entries']:,}")
    print(f"   Deleted Files: {mft_stats['deleted_entries']:,}")
    print(f"   Fully Recoverable: {mft_stats['recoverable_files']:,}")
    print(f"   Partially Recoverable: {mft_stats['partially_recoverable']:,}")
    print(f"   Non-Recoverable: {mft_stats['non_recoverable']:,}")
    print(f"   Timestomped Files: {mft_stats['timestomped_files']:,}")
    print(f"   ADS Detected: {mft_stats['ads_detected']:,}")
    print(f"   Anomalies: {mft_stats['anomalies_detected']:,}")
    print(f"{'='*70}")

    # Try to open the report
    print(f"\n🌐 Opening report in browser...")

    try:
        import webbrowser
        abs_path = os.path.abspath(demo_file)
        webbrowser.open(f"file://{abs_path}")
        print(f"✅ Report opened in default browser!")
    except Exception as e:
        print(f"⚠️  Could not auto-open browser: {e}")
        print(f"📂 Manually open: {os.path.abspath(demo_file)}")

    print(f"\n{'='*70}")
    print(f"🎉 DEMO COMPLETE!")
    print(f"{'='*70}")
    print(f"\n📋 What you can see in the report:")
    print(f"   ✅ Summary statistics cards")
    print(f"   ✅ Deleted files table with recovery status")
    print(f"   ✅ Timestomped files (anti-forensics detection)")
    print(f"   ✅ Alternate Data Streams (ADS)")
    print(f"   ✅ Timeline of file deletions")
    print(f"   ✅ Color-coded recovery badges")
    print(f"   ✅ Anomalies section")
    print(f"   ✅ Professional UI matching your existing tabs")
    print(f"\n💡 This is how the MFT Analysis tab will look on Windows!")
    print(f"   (With real data from pytsk3 parsing actual $MFT)")
    print(f"\n{'='*70}\n")

    return demo_file


if __name__ == "__main__":
    print("\n" + "🎬 "*20)
    print("MFT ANALYSIS - DEMO MODE")
    print("Simulating MFT parsing without Windows or pytsk3")
    print("🎬 "*20 + "\n")

    try:
        demo_file = generate_demo_report()

        print(f"\n✅ SUCCESS! Check out the MFT Analysis UI in:")
        print(f"   📄 {demo_file}")
        print(f"\n🔍 The UI shows:")
        print(f"   • Real-world deleted file scenarios")
        print(f"   • Timestomping detection (anti-forensics)")
        print(f"   • Alternate Data Streams (malware hiding)")
        print(f"   • Recovery assessment (FULL/PARTIAL/METADATA_ONLY)")
        print(f"   • Professional forensic investigator interface")

    except Exception as e:
        print(f"\n❌ Error generating demo: {e}")
        import traceback
        traceback.print_exc()
