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
from templates.html_generator import generate_html_header, generate_html_footer, copy_assets_to_report, generate_threat_dashboard
from core.regex_analyzer import RegexAnalyzer
from core.hash_analyzer import HashAnalyzer


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
    all_forensic_data = []  # Collect all output for regex analysis

    with open(html_file, "w", encoding="utf-8") as f:
        # Write HTML header
        f.write(generate_html_header(timestamp, assets_path))

        # Write navigation buttons
        for category in COMMANDS.keys():
            if category not in ['regex_analysis', 'hash_analysis']:  # Skip analysis placeholders
                f.write(f'            <a href="#" class="nav-btn" onclick="scrollToCategory(\'{category}\'); return false;">📋 {category.upper()}</a>\n')

        # Add analysis buttons
        f.write(f'            <a href="#" class="nav-btn" onclick="scrollToCategory(\'regex_analysis\'); return false;" style="background: #e74c3c;">🔍 REGEX ANALYSIS</a>\n')
        f.write(f'            <a href="#" class="nav-btn" onclick="scrollToCategory(\'hash_analysis\'); return false;" style="background: #9b59b6;">🔐 HASH ANALYSIS</a>\n')

        f.write('            <a href="#" class="nav-btn" onclick="expandAll(); return false;" style="background: #27ae60;">➕ Expand All</a>\n')
        f.write('            <a href="#" class="nav-btn" onclick="collapseAll(); return false;" style="background: #e74c3c;">➖ Collapse All</a>\n')
        f.write('        </div>\n\n        <div class="content">\n')

        # Process each category
        for category, cmds in COMMANDS.items():
            # Skip analysis categories - we'll process them at the end
            if category in ['regex_analysis', 'hash_analysis']:
                continue

            print(f"[+] Collecting {category} information...")

            f.write(f'            <div id="{category}" class="category">\n')
            f.write(f'                <h2>📌 {category.upper()}</h2>\n')

            # Process each command in the category
            for idx, cmd in enumerate(cmds):
                command_id = f"{category}_cmd_{idx}"

                # Auto-detect and execute
                output, cmd_type = execute(cmd)

                # Collect data for regex analysis
                if output and output.strip() and not output.startswith("❌"):
                    all_forensic_data.append(f"\n=== {category.upper()} - {cmd[:80]} ===\n{output}\n")

                # Display detected type
                print(f"    └─ Detected: {cmd_type.upper()} - {cmd[:50]}...")

                badge = "PS" if cmd_type == "powershell" else "CMD"
                header_class = "powershell" if cmd_type == "powershell" else ""

                # Get user-friendly description or fallback to command
                cmd_description = COMMAND_DESCRIPTIONS.get(cmd, cmd[:100])

                f.write(f'                <div class="command-section">\n')
                f.write(f'                    <div class="command-header {header_class}" onclick="toggleOutput(\'{command_id}\')">\n')
                f.write(f'                        <span class="command-title">\n')
                f.write(f'                            <span class="cmd-badge">{badge}</span>\n')
                f.write(f'                            {escape_html(cmd_description)}{"..." if len(cmd_description) > 100 else ""}\n')
                f.write(f'                        </span>\n')
                f.write(f'                        <span id="{command_id}-icon" class="toggle-icon">▼</span>\n')
                f.write(f'                    </div>\n')

                if output and output.strip():
                    f.write(f'                    <div id="{command_id}" class="command-output" style="display: none;">\n')
                    # Use table parser instead of raw pre tags
                    table_html = parse_to_table(output, cmd)
                    f.write(f'                        {table_html}\n')
                    f.write(f'                    </div>\n')
                else:
                    f.write(f'                    <div id="{command_id}" class="command-output" style="display: none;">\n')
                    f.write(f'                        <p class="empty-output">No output or command failed</p>\n')
                    f.write(f'                    </div>\n')

                f.write(f'                </div>\n\n')

            f.write(f'            </div>\n\n')

        # Now perform Regex Analysis
        print(f"\n[+] 🔍 Performing Regex Analysis on collected data...")
        combined_forensic_text = "\n".join(all_forensic_data)
        regex_results = regex_analyzer.analyze_text(combined_forensic_text)

        f.write(f'            <div id="regex_analysis" class="category">\n')
        f.write(f'                <h2>🔍 REGEX PATTERN ANALYSIS</h2>\n')
        f.write(f'                <div class="command-section">\n')

        # Generate threat dashboard if critical threats found
        if regex_results['threat_score'] > 50:
            threat_data = {
                'threat_level': regex_results['threat_level'],
                'threat_score': regex_results['threat_score'],
                'total_iocs': len(regex_results['iocs']),
                'critical_findings': len(regex_results['suspicious_patterns'].get('CREDENTIALS', [])) +
                                   len(regex_results['suspicious_patterns'].get('MALWARE', [])),
                'total_commands': len(all_forensic_data)
            }
            f.write(generate_threat_dashboard(threat_data))

        regex_html = regex_analyzer.generate_report(regex_results)
        f.write(regex_html)
        f.write(f'                </div>\n')
        f.write(f'            </div>\n\n')

        print(f"    ✅ Found {len(regex_results['iocs'])} IOCs")
        print(f"    ⚠️  Threat Level: {regex_results['threat_level']} (Score: {regex_results['threat_score']})")

        # Now perform Hash Analysis (OS-agnostic)
        print(f"\n[+] 🔐 Performing Hash Analysis...")
        f.write(f'            <div id="hash_analysis" class="category">\n')
        f.write(f'                <h2>🔐 FILE HASH ANALYSIS</h2>\n')

        # Get common evidence directories for current OS
        file_hashes = []
        evidence_dirs = hash_analyzer.get_common_evidence_directories()

        if evidence_dirs:
            print(f"    └─ Detected {len(evidence_dirs)} evidence directories on {sys.platform}")

            # Scan multiple directories
            file_hashes = hash_analyzer.scan_multiple_directories(
                evidence_dirs,
                max_files_per_dir=30,  # Limit per directory to avoid huge scans
                extensions=None  # Will use default suspicious extensions
            )

            # Log scanned directories
            for dir_path in hash_analyzer.scanned_paths:
                print(f"    └─ Scanned: {dir_path}")

            # Count actual file results (not errors)
            valid_hashes = [f for f in file_hashes if not f.get('error') and not f.get('info')]
            print(f"    ✅ Analyzed {len(valid_hashes)} files")

            if hash_analyzer.malware_detections:
                print(f"    🚨 MALWARE DETECTED: {len(hash_analyzer.malware_detections)} known malicious files!")
            if hash_analyzer.suspicious_files:
                print(f"    ⚠️  Suspicious files: {len(hash_analyzer.suspicious_files)}")
        else:
            # Fallback: scan current report directory for demonstration
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

        # Always populate results, even if empty
        if file_hashes:
            # Format results for parser
            hash_results_dict = {
                'file_hashes': file_hashes,
                'malware_detections': hash_analyzer.malware_detections,
                'suspicious_files': hash_analyzer.suspicious_files,
                'duplicates': hash_analyzer.get_duplicate_files()
            }

        # Always populate results, even if empty
        if file_hashes:
            # Format results for parser
            hash_results_dict = {
                'file_hashes': file_hashes,
                'malware_detections': hash_analyzer.malware_detections,
                'suspicious_files': hash_analyzer.suspicious_files,
                'duplicates': hash_analyzer.get_duplicate_files()
            }

            hash_html = parse_hash_analysis_output(hash_results_dict)
            f.write(f'                <div class="command-section">\n')
            f.write(hash_html)
            f.write(f'                </div>\n')
        else:
            # Even with no files, show a message
            f.write(f'                <div class="command-section">\n')
            f.write(f'                    <p class="empty-output">No files found to analyze. Install the tool on the target system for full forensic analysis.</p>\n')
            f.write(f'                </div>\n')

        f.write(f'            </div>\n\n')        # Write HTML footer
        f.write(generate_html_footer(assets_path))

    print(f"\n✅ Done! Open the HTML report:")
    print(f"📄 {html_file}")
    print(f"\n💡 Commands were automatically detected and executed!")
    print(f"🔵 Blue headers = CMD commands")
    print(f"🟦 Dark blue headers = PowerShell commands")
    print(f"📊 Data displayed in formatted tables")


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
