"""
Windows Forensics Tool - Modular Version
========================================

Main entry point for the forensic data collection tool.
This version uses a modular structure with separated components:
- config/commands.py: Command definitions
- core/executor.py: Command execution logic
- core/parsers.py: Output parsing and table generation
- templates/html_generator.py: HTML template generation
- assets/styles.css: Stylesheet
- assets/script.js: JavaScript functions

Author: Forensics Tool Team
Date: November 2025
"""

import os
import sys
from datetime import datetime

# Import our modules
from config.commands import COMMANDS, COMMAND_DESCRIPTIONS
from core.executor import execute, is_admin, run_as_admin
from core.parsers import parse_to_table, escape_html, parse_regex_analysis_output, parse_hash_analysis_output
from templates.html_generator import (
    generate_html_header,
    generate_html_footer,
    copy_assets_to_report,
    generate_threat_dashboard,
    generate_dashboard_tab,
    generate_activity_items,
    generate_os_commands_tab,
    generate_os_command_sections,
    generate_hash_tab_interactive,
    generate_ioc_scanner_tab,
    generate_pii_tab,
    generate_encrypted_files_tab
)
from templates.browser_history_tab import generate_browser_history_tab
from core.regex_analyzer import RegexAnalyzer
from core.hash_analyzer import HashAnalyzer
from core.file_scanner import FileScanner
from core.ioc_scanner import IOCScanner
from core.encrypted_file_scanner import EncryptedFileScanner
from core.browser_analyzer import BrowserHistoryAnalyzer


def run_forensic_collection():
    """Main function to collect forensic data and generate HTML report"""

    # Check admin status
    if sys.platform == 'win32':
        if is_admin():
            print("✅ Running with Administrator privileges")
        else:
            print("⚠️  WARNING: Not running as Administrator")
            print("   Some commands may fail or produce incomplete results.")
            print("   For full forensic data, run this script as Administrator.\n")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = f"Forensic_Report_{timestamp}"
    os.makedirs(report_path, exist_ok=True)

    html_file = os.path.join(report_path, "forensic_report.html")

    print(f"📊 Generating HTML forensic report...")
    print(f"📁 Saving to: {report_path}")
    print(f"🤖 Auto-detecting command types...\n")

    # Copy assets (CSS and JavaScript) to report folder
    if copy_assets_to_report(report_path):
        print("✅ Assets (CSS/JS) copied to report folder")
        assets_path = "./assets"  # Relative path within report folder
    else:
        print("⚠️  Assets folder not found, using embedded styles")
        assets_path = "../assets"  # Fallback to parent assets

    # Initialize analyzers and data collectors
    regex_analyzer = RegexAnalyzer()
    hash_analyzer = HashAnalyzer()
    ioc_scanner = IOCScanner()
    all_forensic_data = []  # Collect all output for regex analysis

    # Collect command results organized by category for the new UI
    os_results = {}
    activity_log = []

    # First, collect all command results
    for category, cmds in COMMANDS.items():
        # Skip analysis categories - we'll process them separately
        if category in ['regex_analysis', 'hash_analysis']:
            continue

        print(f"[+] Collecting {category} information...")
        os_results[category] = []

        # Process each command in the category
        for idx, cmd in enumerate(cmds):
            # Auto-detect and execute
            output, cmd_type = execute(cmd)

            # Collect data for regex analysis
            if output and output.strip() and not output.startswith("❌"):
                all_forensic_data.append(f"\n=== {category.upper()} - {cmd[:80]} ===\n{output}\n")

            # Display detected type
            print(f"    └─ Detected: {cmd_type.upper()} - {cmd[:50]}...")

            # Get user-friendly description or fallback to command
            cmd_description = COMMAND_DESCRIPTIONS.get(cmd, cmd[:100])

            # Parse output to HTML table
            if output and output.strip():
                table_html = parse_to_table(output, cmd)
            else:
                table_html = '<p class="empty-output">No output or command failed</p>'

            # Store result for new UI
            os_results[category].append({
                'description': cmd_description,
                'output': table_html,
                'type': 'PS' if cmd_type == 'powershell' else 'CMD',
                'success': bool(output and output.strip() and not output.startswith("❌"))
            })

    # Perform Regex Analysis
    print(f"\n[+] 🔍 Performing Regex Analysis on collected data...")
    combined_forensic_text = "\n".join(all_forensic_data)
    regex_results = regex_analyzer.analyze_text(combined_forensic_text)

    print(f"    ✅ Found {len(regex_results['iocs'])} IOCs")
    print(f"    ⚠️  Threat Level: {regex_results['threat_level']} (Score: {regex_results['threat_score']})")

    # Add to activity log
    activity_log.append({
        'type': 'regex analysis',
        'matches': len(regex_results['iocs'])
    })

    # Perform Hash Analysis (OS-agnostic)
    print(f"\n[+] 🔐 Performing Hash Analysis...")
    file_hashes = []
    evidence_dirs = hash_analyzer.get_common_evidence_directories()

    if evidence_dirs:
        print(f"    └─ Detected {len(evidence_dirs)} evidence directories on {sys.platform}")
        file_hashes = hash_analyzer.scan_multiple_directories(
            evidence_dirs,
            max_files_per_dir=30,
            extensions=None
        )

        for dir_path in hash_analyzer.scanned_paths:
            print(f"    └─ Scanned: {dir_path}")

        valid_hashes = [f for f in file_hashes if not f.get('error') and not f.get('info')]
        print(f"    ✅ Analyzed {len(valid_hashes)} files")

        if hash_analyzer.malware_detections:
            print(f"    🚨 MALWARE DETECTED: {len(hash_analyzer.malware_detections)} known malicious files!")
        if hash_analyzer.suspicious_files:
            print(f"    ⚠️  Suspicious files: {len(hash_analyzer.suspicious_files)}")
    else:
        print(f"    ⚠️  No standard evidence directories found")
        print(f"    └─ Scanning current directory as example...")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_hashes = hash_analyzer.scan_evidence_directory(
            current_dir,
            max_files=20,
            extensions=['.py', '.txt', '.log', '.json']
        )
        valid_hashes = [f for f in file_hashes if not f.get('error') and not f.get('info')]
        print(f"    ✅ Analyzed {len(valid_hashes)} files (demo mode)")

    # Add to activity log
    activity_log.append({
        'type': 'hash analysis',
        'matches': len(file_hashes) if file_hashes else 0
    })

    # Perform PII Detection Scan
    print(f"\n[+] 🔍 Performing PII Detection Analysis...")
    pii_scanner = FileScanner()
    pii_results = []

    try:
        # Focus on key directories that likely contain PII
        from pathlib import Path
        scan_dirs = []

        # Add Downloads directory (most likely to contain PII documents)
        downloads_path = str(Path.home() / 'Downloads')
        if os.path.exists(downloads_path):
            scan_dirs.append(downloads_path)

        # Add Desktop directory
        desktop_path = str(Path.home() / 'Desktop')
        if os.path.exists(desktop_path):
            scan_dirs.append(desktop_path)

        # Add Documents directory
        documents_path = str(Path.home() / 'Documents')
        if os.path.exists(documents_path):
            scan_dirs.append(documents_path)

        if scan_dirs:
            print(f"    └─ Scanning {len(scan_dirs)} high-value directories for PII")
            pii_results = pii_scanner.scan_specific_directories(scan_dirs, max_files_per_dir=25)

            pii_files = len(pii_results)
            total_pii_items = sum(len(result.get('analysis_results', {}).get('pii_findings', [])) for result in pii_results)
            high_risk_files = len([r for r in pii_results if r.get('analysis_results', {}).get('privacy_risk_score', 0) >= 8])

            print(f"    ✅ Found {pii_files} files containing PII")
            print(f"    📊 Total PII items: {total_pii_items}")
            if high_risk_files > 0:
                print(f"    🚨 High-risk files: {high_risk_files}")
        else:
            print(f"    ⚠️  No standard user directories found for PII scanning")

    except Exception as e:
        print(f"    ❌ PII scanning error: {str(e)}")
        pii_results = []

    # Add to activity log
    activity_log.append({
        'type': 'pii detection',
        'matches': len(pii_results)
    })

    # Perform IOC Scan Analysis
    print(f"\n[+] 🛡️  Performing IOC (Indicators of Compromise) Scan...")
    ioc_results = ioc_scanner.scan_text(combined_forensic_text)

    print(f"    ✅ Threat Level: {ioc_results['threat_level']} (Score: {ioc_results['threat_score']})")
    print(f"    📊 Total IOCs Found: {ioc_results['total_iocs']}")
    print(f"    🔴 Critical: {ioc_results['severity_counts']['CRITICAL']}")
    print(f"    🟠 High: {ioc_results['severity_counts']['HIGH']}")
    print(f"    🟡 Medium: {ioc_results['severity_counts']['MEDIUM']}")
    print(f"    🟢 Low: {ioc_results['severity_counts']['LOW']}")

    if ioc_results['total_iocs'] > 0:
        print(f"    ⚠️  Categories detected: {', '.join(ioc_results['findings_by_category'].keys())}")

    # Add to activity log
    activity_log.append({
        'type': 'ioc scan analysis',
        'matches': ioc_results['total_iocs']
    })

    # IOC scan activity
    activity_log.append({
        'type': 'threat intelligence',
        'matches': 2  # Placeholder
    })

    # Perform Encrypted Files Detection
    print(f"\n[+] 🔐 Performing Encrypted Files Detection...")
    encrypted_scanner = EncryptedFileScanner()
    encrypted_files = []

    try:
        print(f"    └─ Platform: {sys.platform}")
        print(f"    └─ Scanning user directories (excluding system files)...")

        encrypted_files = encrypted_scanner.scan_user_directories(max_files_per_dir=250)

        print(f"    ✅ Scanned {encrypted_scanner.stats['total_scanned']} files")
        print(f"    🔒 Found {encrypted_scanner.stats['encrypted_found']} encrypted files")

        if encrypted_scanner.stats['efs_files'] > 0:
            print(f"    🔐 Windows EFS: {encrypted_scanner.stats['efs_files']}")
        if encrypted_scanner.stats['password_protected'] > 0:
            print(f"    🔑 Password-Protected: {encrypted_scanner.stats['password_protected']}")
        if encrypted_scanner.stats['encrypted_containers'] > 0:
            print(f"    💾 Encrypted Containers: {encrypted_scanner.stats['encrypted_containers']}")
        if encrypted_scanner.stats['filevault_files'] > 0:
            print(f"    🍎 macOS Encrypted: {encrypted_scanner.stats['filevault_files']}")

    except Exception as e:
        print(f"    ❌ Encrypted file scanning error: {str(e)}")

    encrypted_data = encrypted_scanner.generate_report_data()

    # Add to activity log
    activity_log.append({
        'type': 'encrypted file scan',
        'matches': len(encrypted_files)
    })

    # Perform Browser History Analysis
    print(f"\n{'='*70}")
    print(f"🌐 BROWSER HISTORY ANALYSIS")
    print(f"{'='*70}")
    browser_analyzer = BrowserHistoryAnalyzer()
    browser_history = {}
    browser_stats = {}

    try:
        # Get 1 YEAR of history with NO LIMIT on entries
        # This retrieves ALL available history from the past 365 days
        browser_history = browser_analyzer.analyze_all_browsers(
            limit=None,      # No limit - get ALL entries
            days_back=365    # Last 1 year
        )
        browser_stats = browser_analyzer.get_statistics(browser_history)

        print(f"{'='*70}")
        print(f"✅ BROWSER HISTORY SUMMARY:")
        print(f"   Browsers analyzed: {browser_stats['browsers_found']}")
        print(f"   Total entries: {browser_stats['total_entries']}")
        print(f"   Total visits: {browser_stats['total_visits']}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ Browser history error: {str(e)}")

    # Add to activity log
    activity_log.append({
        'type': 'browser history',
        'matches': browser_stats.get('total_entries', 0)
    })

    # Now generate the modern HTML report
    with open(html_file, "w", encoding="utf-8") as f:
        # Write HTML header with modern UI
        f.write(generate_html_header(timestamp, assets_path))

        # Generate Dashboard Tab
        stats = {
            'total_cases': 3,
            'active_cases': 3,
            'evidence_items': 0,
            'analysis_logs': len(activity_log),
            'timestamp': timestamp
        }
        f.write(generate_dashboard_tab(stats, activity_log, {}))

        # Generate OS Commands Tab
        f.write(generate_os_commands_tab(os_results, "Windows"))

        # Generate Hash Analysis Tab (NEW INTERACTIVE VERSION)
        f.write(generate_hash_tab_interactive(file_hashes if file_hashes else []))

        # Generate PII Detection Tab (NEW)
        f.write(generate_pii_tab(pii_results))

        # Generate Browser History Tab (NEW)
        f.write(generate_browser_history_tab(browser_history, browser_stats))

        # Generate Encrypted Files Tab (NEW)
        f.write(generate_encrypted_files_tab(encrypted_data))

        # Generate Regex Analysis Tab
        f.write(f'    <div id="tab-regex" class="tab-content">\n')
        f.write(f'        <div class="tab-header">\n')
        f.write(f'            <h1>Regex Pattern Analysis</h1>\n')
        f.write(f'        </div>\n')
        f.write(f'        <div class="card">\n')

        # Generate threat dashboard if critical threats found
        if regex_results['threat_score'] > 50:
            threat_data = {
                'threat_level': regex_results['threat_level'],
                'threat_score': regex_results['threat_score'],
                'total_iocs': len(regex_results['iocs']),
                'critical_findings': len(regex_results['suspicious_patterns'].get('CREDENTIALS', [])) +
                                   len(regex_results['suspicious_patterns'].get('MALWARE', [])),
                'total_commands': len(all_forensic_data),
                'files_hashed': len(file_hashes) if file_hashes else 0
            }
            f.write(generate_threat_dashboard(threat_data))

        regex_html = regex_analyzer.generate_report(regex_results)
        f.write(regex_html)
        f.write(f'        </div>\n')
        f.write(f'    </div>\n\n')

        # Generate IOC Scanner Tab (NEW FUNCTIONAL VERSION WITH RESULTS)
        f.write(generate_ioc_scanner_tab(ioc_results))

        # Write HTML footer
        f.write(generate_html_footer(assets_path))

    print(f"\n✅ Done! Open the HTML report:")
    print(f"📄 {html_file}")
    print(f"\n💡 Modern LEA Triage Dashboard Generated!")
    print(f"🎨 Features:")
    print(f"   • Dark professional theme")
    print(f"   • Tab-based navigation (Dashboard/Commands/Hash/PII/Regex/IOC)")
    print(f"   • OS selector (Windows/Linux/macOS)")
    print(f"   • Interactive cards and search")
    print(f"   • Real-time stats and activity feed")
    print(f"\n� Report includes:")
    print(f"   • {len(all_forensic_data)} forensic command results")
    print(f"   • {len(regex_results['iocs'])} IOCs detected")
    print(f"   • {len(file_hashes) if file_hashes else 0} files analyzed")
    print(f"   • Threat Score: {regex_results['threat_score']}/100")


if __name__ == "__main__":
    # Check if running on Windows
    if sys.platform == 'win32':
        # If not admin, offer to elevate
        if not is_admin():
            print("=" * 60)
            print("🔒 ADMINISTRATOR PRIVILEGES REQUIRED")
            print("=" * 60)
            print("\nThis forensic tool needs Administrator privileges for:")
            print("  • netstat -naob (process-to-connection mapping)")
            print("  • USB device history and events")
            print("  • System event logs")
            print("  • Complete process information")
            print("\nOptions:")
            print("  1. Restart with Administrator privileges (Recommended)")
            print("  2. Continue without admin (Limited data)")
            print("=" * 60)

            choice = input("\nYour choice (1 or 2): ").strip()

            if choice == "1":
                print("\n🔄 Restarting with Administrator privileges...")
                print("   (You may see a UAC prompt - click 'Yes')\n")
                run_as_admin()
            else:
                print("\n⚠️  Continuing without Administrator privileges...")
                print("   Some commands may fail.\n")

    run_forensic_collection()
