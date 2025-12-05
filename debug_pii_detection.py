#!/usr/bin/env python3
"""
Debug PAN/Aadhar Detection Test
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.regex_analyzer import RegexAnalyzer
from core.file_scanner import FileScanner

def debug_pii_detection():
    """Test PAN and Aadhar card detection with debug output"""

    print("🔍 Debugging PAN/Aadhar Detection")
    print("=" * 50)

    # Initialize components
    regex_analyzer = RegexAnalyzer()
    file_scanner = FileScanner(regex_analyzer)

    # Lower thresholds significantly for debugging
    file_scanner.configure_scan(
        max_file_size_mb=50,
        min_privacy_score=1,     # Very low threshold
        min_pii_count=1,         # Just 1 PII item needed
        min_investigative_score=1, # Very low threshold
        filter_screenshots=False  # Don't filter anything for debug
    )

    print("📊 DEBUG Configuration:")
    print(f"   Min Privacy Score: {file_scanner.scan_config['min_privacy_score']}")
    print(f"   Min PII Count: {file_scanner.scan_config['min_pii_count']}")
    print(f"   Min Investigation Score: {file_scanner.scan_config['min_investigative_score']}")
    print(f"   Filter Screenshots: {file_scanner.scan_config['filter_screenshots']}")
    print()

    # Test some sample PII text
    test_texts = [
        "My PAN card number is ABCDE1234F and my phone is 9876543210",
        "Aadhar: 1234 5678 9012 and email: test@example.com",
        "Credit card: 4532 1234 5678 9012 expires 12/25",
        "Account number: 123456789012 and IFSC: SBIN0001234"
    ]

    print("🧪 Testing PII Detection Patterns:")
    for i, text in enumerate(test_texts, 1):
        print(f"\n{i}. Testing: {text}")
        result = regex_analyzer.analyze_text(text)

        if isinstance(result, dict):
            pii_count = len(result.get('pii_findings', []))
            privacy_score = result.get('privacy_risk_score', 0)
            print(f"   📊 Privacy Score: {privacy_score}")
            print(f"   📄 PII Items: {pii_count}")

            for pii in result.get('pii_findings', []):
                print(f"      - {pii.get('type', 'Unknown')}: {pii.get('value', 'N/A')}")
        else:
            print(f"   ❌ Unexpected result type: {type(result)}")

    # Now scan actual files with debug mode
    print(f"\n🔍 Scanning actual files (DEBUG MODE)...")
    results = file_scanner.scan_common_directories(max_files=50)

    print(f"\n📋 DEBUG Scan Results:")
    print(f"   Total files found: {len(results)}")

    if results:
        print(f"\n📄 Files with PII detected:")
        for i, result in enumerate(results[:10], 1):  # Show first 10
            file_name = result['file_name']
            pii_count = len(result['analysis_results'].get('pii_findings', []))
            privacy_score = result['analysis_results'].get('privacy_risk_score', 0)
            invest_score = result.get('investigative_score', 0)

            print(f"   {i}. {file_name}")
            print(f"      📊 Privacy Score: {privacy_score}")
            print(f"      🎯 Investigation Score: {invest_score}")
            print(f"      📄 PII Items: {pii_count}")

            # Show PII types found
            pii_types = []
            for pii in result['analysis_results'].get('pii_findings', []):
                pii_types.append(pii.get('type', 'Unknown'))

            if pii_types:
                print(f"      🔍 PII Types: {', '.join(set(pii_types))}")
            print()
    else:
        print("   ❌ No files detected - investigating further...")

        # Check if any files are being scanned at all
        print(f"\n🔧 Debugging file scanning process...")

        # Try scanning a specific directory with more debug output
        import os
        from pathlib import Path

        home_dir = Path.home()
        test_dirs = [
            str(home_dir / 'Desktop'),
            str(home_dir / 'Documents'),
            str(home_dir / 'Downloads')
        ]

        for test_dir in test_dirs:
            if os.path.exists(test_dir):
                print(f"\n📂 Debug scanning: {test_dir}")
                files_found = []

                try:
                    for root, dirs, files in os.walk(test_dir):
                        for file in files[:5]:  # Just check first 5 files
                            file_path = os.path.join(root, file)
                            file_ext = Path(file).suffix.lower()

                            if file_scanner._is_supported_file(file_ext):
                                print(f"   📄 Supported file: {file} ({file_ext})")
                                files_found.append(file_path)
                            else:
                                print(f"   ❌ Unsupported file: {file} ({file_ext})")

                        if files_found:
                            break  # Don't go too deep

                    print(f"   Found {len(files_found)} supported files")

                except Exception as e:
                    print(f"   ❌ Error scanning {test_dir}: {e}")

    return results

if __name__ == "__main__":
    try:
        results = debug_pii_detection()
        print(f"\n✨ Debug completed!")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()