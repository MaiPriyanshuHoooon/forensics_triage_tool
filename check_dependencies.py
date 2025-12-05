#!/usr/bin/env python3
"""
Dependency Checker for Forensic Triage Tool
============================================
Checks if all required and optional dependencies are installed
Provides installation instructions for missing packages
"""

import sys
import platform

def check_module(module_name, package_name=None, optional=False, windows_only=False):
    """
    Check if a module can be imported

    Args:
        module_name: The name to use in import statement
        package_name: The pip package name (if different from module_name)
        optional: Whether this is an optional dependency
        windows_only: Whether this is Windows-only
    """
    if package_name is None:
        package_name = module_name

    # Skip Windows-only packages on non-Windows
    if windows_only and sys.platform != 'win32':
        return None

    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def main():
    print("=" * 70)
    print("Forensic Triage Tool - Dependency Checker")
    print("=" * 70)
    print(f"\nPython Version: {sys.version}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}\n")

    results = {
        'required': [],
        'optional': [],
        'windows_only': [],
        'missing_required': [],
        'missing_optional': [],
        'missing_windows': []
    }

    # Required dependencies
    print("📦 Required Dependencies:")
    print("-" * 70)

    required = [
        ('requests', 'requests', 'VirusTotal API integration'),
    ]

    for module, package, description in required:
        status = check_module(module, package)
        if status:
            print(f"✅ {package:20} - {description}")
            results['required'].append(package)
        else:
            print(f"❌ {package:20} - {description}")
            results['missing_required'].append(package)

    # Windows-only dependencies
    if sys.platform == 'win32':
        print("\n🪟 Windows-Only Dependencies:")
        print("-" * 70)

        windows_deps = [
            ('win32evtlog', 'pywin32', 'Event Log and Registry analysis'),
        ]

        for module, package, description in windows_deps:
            status = check_module(module, package, windows_only=True)
            if status:
                print(f"✅ {package:20} - {description}")
                results['windows_only'].append(package)
            else:
                print(f"❌ {package:20} - {description}")
                results['missing_windows'].append(package)
    else:
        print("\n🪟 Windows-Only Dependencies: (Skipped - not on Windows)")

    # Optional document processing dependencies
    print("\n📄 Optional Document Processing Dependencies:")
    print("-" * 70)

    optional = [
        ('PyPDF2', 'PyPDF2', 'PDF text extraction'),
        ('docx', 'python-docx', 'Word document processing'),
        ('openpyxl', 'openpyxl', 'Excel spreadsheet processing'),
        ('PIL', 'Pillow', 'Image processing for OCR'),
        ('pytesseract', 'pytesseract', 'OCR text extraction'),
        ('cv2', 'opencv-python', 'Video frame extraction'),
        ('pandas', 'pandas', 'Data processing for CSV/Excel'),
    ]

    for module, package, description in optional:
        status = check_module(module, package, optional=True)
        if status:
            print(f"✅ {package:20} - {description}")
            results['optional'].append(package)
        else:
            print(f"⚠️  {package:20} - {description}")
            results['missing_optional'].append(package)

    # Summary
    print("\n" + "=" * 70)
    print("📊 Summary:")
    print("=" * 70)

    total_required = len(required)
    total_windows = len(windows_deps) if sys.platform == 'win32' else 0
    total_optional = len(optional)

    installed_required = len(results['required'])
    installed_windows = len(results['windows_only'])
    installed_optional = len(results['optional'])

    print(f"✅ Required:    {installed_required}/{total_required} installed")
    if sys.platform == 'win32':
        print(f"🪟 Windows:     {installed_windows}/{total_windows} installed")
    print(f"📄 Optional:    {installed_optional}/{total_optional} installed")

    # Installation instructions for missing packages
    if results['missing_required'] or results['missing_windows'] or results['missing_optional']:
        print("\n" + "=" * 70)
        print("🔧 Installation Instructions:")
        print("=" * 70)

        if results['missing_required']:
            print("\n❗ Missing REQUIRED dependencies:")
            print(f"   pip install {' '.join(results['missing_required'])}")

        if results['missing_windows'] and sys.platform == 'win32':
            print("\n❗ Missing Windows-only dependencies:")
            print(f"   pip install {' '.join(results['missing_windows'])}")
            if 'pywin32' in results['missing_windows']:
                print("   python Scripts\\pywin32_postinstall.py -install")

        if results['missing_optional']:
            print("\n⚠️  Missing optional dependencies (for document scanning):")
            print(f"   pip install {' '.join(results['missing_optional'])}")
            if 'pytesseract' in results['missing_optional']:
                print("\n   ⚠️  pytesseract also requires Tesseract-OCR binary:")
                if sys.platform == 'win32':
                    print("      Windows: https://github.com/UB-Mannheim/tesseract/wiki")
                elif sys.platform == 'darwin':
                    print("      macOS: brew install tesseract")
                else:
                    print("      Linux: sudo apt-get install tesseract-ocr")

        print("\n💡 Install all dependencies at once:")
        print("   pip install -r requirements.txt")
    else:
        print("\n✨ All dependencies are installed! You're ready to go!")

    # Feature availability
    print("\n" + "=" * 70)
    print("🎯 Feature Availability:")
    print("=" * 70)

    features = {
        "✅ OS Commands": True,  # Always available (subprocess built-in)
        "✅ Browser History": True,  # Always available (sqlite3 built-in)
        "✅ IOC Scanner": True,  # Always available (re built-in)
        "✅ Encrypted Files": True,  # Always available (os, pathlib built-in)
        "✅ Hash Analysis": 'requests' in results['required'],
        "✅ PII Detection (Basic)": True,  # Regex always works
        "✅ PII Detection (PDF)": 'PyPDF2' in results['optional'],
        "✅ PII Detection (Word)": 'python-docx' in results['optional'],
        "✅ PII Detection (Excel)": 'openpyxl' in results['optional'],
        "✅ PII Detection (Images)": 'Pillow' in results['optional'] and 'pytesseract' in results['optional'],
        "✅ PII Detection (Videos)": 'opencv-python' in results['optional'],
        "✅ Registry Analysis": 'pywin32' in results['windows_only'] if sys.platform == 'win32' else False,
        "✅ Event Log Analysis": 'pywin32' in results['windows_only'] if sys.platform == 'win32' else False,
    }

    for feature, available in features.items():
        if isinstance(available, bool):
            if available:
                print(f"✅ {feature}")
            else:
                if 'Registry' in feature or 'Event Log' in feature:
                    if sys.platform != 'win32':
                        print(f"⏭️  {feature} (Windows-only feature)")
                    else:
                        print(f"❌ {feature} (missing pywin32)")
                else:
                    print(f"❌ {feature}")

    print("\n" + "=" * 70)

    # Exit with error code if required dependencies are missing
    if results['missing_required'] or (sys.platform == 'win32' and results['missing_windows']):
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
