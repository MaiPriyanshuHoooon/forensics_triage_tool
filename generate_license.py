#!/usr/bin/env python3
"""
License Generator CLI Tool
==========================
Command-line utility for generating licenses (vendor/admin use only)

Usage:
    python generate_license.py --device-id <ID> --type trial
    python generate_license.py --device-id <ID> --type full
    python generate_license.py --device-id <ID> --type subscription --days 365

Examples:
    # Generate 7-day trial
    python generate_license.py --device-id abc123def456 --type trial

    # Generate perpetual license
    python generate_license.py --device-id abc123def456 --type full

    # Generate 1-year subscription
    python generate_license.py --device-id abc123def456 --type subscription --days 365
"""

import argparse
import sys
from datetime import datetime, timedelta
from license_manager import LicenseManager


def main():
    parser = argparse.ArgumentParser(
        description='Generate license keys for Windows Forensic Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--device-id',
        required=True,
        help='Customer device ID (obtained from their activation dialog)'
    )

    parser.add_argument(
        '--type',
        choices=['trial', 'full', 'subscription'],
        required=True,
        help='License type: trial (7 days), full (perpetual), or subscription'
    )

    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days for trial/subscription (default: 7 for trial, 365 for subscription)'
    )

    parser.add_argument(
        '--output',
        help='Save license to file instead of printing to console'
    )

    args = parser.parse_args()

    # Initialize license manager
    lm = LicenseManager()

    print("=" * 70)
    print("🔐 Windows Forensic Tool - License Generator")
    print("=" * 70)
    print()

    # Generate license based on type
    try:
        if args.type == 'trial':
            print(f"📝 Generating TRIAL license ({args.days} days)...")
            license_key = lm.generate_trial_license(args.device_id, days=args.days)
            expiration = datetime.now() + timedelta(days=args.days)

        elif args.type == 'full':
            print("📝 Generating PERPETUAL license...")
            license_key = lm.generate_full_license(args.device_id)
            expiration = None

        elif args.type == 'subscription':
            if args.days == 7:  # If using default, set to 365
                args.days = 365
            print(f"📝 Generating SUBSCRIPTION license ({args.days} days)...")
            expiration_date = datetime.now() + timedelta(days=args.days)
            license_key = lm.generate_full_license(args.device_id, expiration_date)
            expiration = expiration_date

        print("✅ License generated successfully!")
        print()
        print("-" * 70)
        print("LICENSE DETAILS:")
        print("-" * 70)
        print(f"Device ID:       {args.device_id}")
        print(f"License Type:    {args.type.upper()}")
        if expiration:
            print(f"Expires:         {expiration.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"Expires:         Never (Perpetual)")
        print(f"Generated:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 70)
        print()
        print("LICENSE KEY:")
        print("-" * 70)
        print(license_key)
        print("-" * 70)
        print()

        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                f.write(license_key)
            print(f"💾 License saved to: {args.output}")
            print()

        print("📧 INSTRUCTIONS FOR CUSTOMER:")
        print("-" * 70)
        print("1. Copy the LICENSE KEY above")
        print("2. Run ForensicTool.exe")
        print("3. In the activation dialog, paste the license key")
        print("4. Click 'Activate License'")
        print("5. Tool will be activated and ready to use!")
        print("-" * 70)
        print()

        return 0

    except Exception as e:
        print(f"❌ ERROR: Failed to generate license")
        print(f"   {str(e)}")
        print()
        return 1


if __name__ == '__main__':
    sys.exit(main())
