#!/usr/bin/env python3
"""
CLI tool for running vulnerability assessments with reachability analysis.

Usage:
    python assessor_cli.py --input results.parquet --output assessments/ [--enable-reachability]
"""

import argparse
import sys
from pathlib import Path
import pandas as pd
import numpy as np
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.backend.schemas.models import VulnCodeIdentification
from src.backend.workflow.vuln_assess.assessor import (
    assess_vulns_df_and_save,
    generate_reachability_report
)


def main():
    parser = argparse.ArgumentParser(
        description='Run vulnerability assessment with optional reachability analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With reachability analysis (recommended)
  python assessor_cli.py --input artifacts/identify/results.parquet --output artifacts/assessments
  
  # Legacy mode without reachability
  python assessor_cli.py --input results.parquet --output assessments/ --no-reachability
  
  # With detailed reporting
  python assessor_cli.py --input results.parquet --output assessments/ --report
        """
    )
    
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to input Parquet file with vulnerability identification results'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Directory path for output assessment files'
    )
    
    parser.add_argument(
        '--enable-reachability',
        dest='reachability',
        action='store_true',
        default=True,
        help='Enable enhanced reachability analysis (default)'
    )
    
    parser.add_argument(
        '--no-reachability',
        dest='reachability',
        action='store_false',
        help='Disable reachability analysis (legacy mode)'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate and display summary report'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Error: Input file not found: {input_path}")
        sys.exit(1)
    
    if not input_path.suffix == '.parquet':
        print(f"⚠️  Warning: Input file should be a Parquet file, got: {input_path.suffix}")
    
    # Create output directory if needed
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load vulnerability data
    if args.verbose:
        print(f"📂 Loading vulnerability data from: {input_path}")
    
    try:
        df = pd.read_parquet(input_path)
        df = df.replace({np.nan: None})
        
        if args.verbose:
            print(f"   Loaded {len(df)} vulnerability records")
        
    except Exception as e:
        print(f"❌ Error loading input file: {e}")
        sys.exit(1)
    
    # Convert to VulnCodeIdentification objects
    try:
        vulns = [VulnCodeIdentification(**row) for row in df.to_dict('records')]
        
        if args.verbose:
            print(f"   Converted to {len(vulns)} VulnCodeIdentification objects")
    
    except Exception as e:
        print(f"❌ Error converting data to VulnCodeIdentification: {e}")
        print("   Ensure input data has all required fields")
        sys.exit(1)
    
    # Run assessment
    mode = "with reachability analysis" if args.reachability else "in legacy mode"
    print(f"\n🔍 Running vulnerability assessment {mode}...")
    
    try:
        assessed_df, output_paths = assess_vulns_df_and_save(
            findings=vulns,
            out_dir=str(output_path),
            enable_reachability=args.reachability
        )
        
        print(f"✅ Assessment complete!")
        print(f"   Assessed {len(assessed_df)} vulnerabilities")
        
    except Exception as e:
        print(f"❌ Error during assessment: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Display output files
    print(f"\n📊 Output files:")
    for file_type, file_path in output_paths.items():
        print(f"   {file_type}: {file_path}")
    
    # Generate and display report if requested
    if args.report:
        print(f"\n📈 Assessment Summary Report:")
        print("=" * 60)
        
        try:
            report = generate_reachability_report(assessed_df)
            
            print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
            print(f"Average Risk Score: {report['avg_risk_score']:.1f}")
            print(f"Risk Score Range: {report['min_risk_score']:.1f} - {report['max_risk_score']:.1f}")
            
            print(f"\nBy Risk Label:")
            for label, count in sorted(
                report['by_risk_label'].items(),
                key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x[0], 0),
                reverse=True
            ):
                percentage = (count / report['total_vulnerabilities']) * 100
                print(f"  {label:8s}: {count:3d} ({percentage:5.1f}%)")
            
            if 'by_reachability_level' in report:
                print(f"\nBy Reachability Level:")
                for level, count in sorted(
                    report['by_reachability_level'].items(),
                    key=lambda x: {'direct': 4, 'indirect': 3, 'unknown': 2, 'unreachable': 1}.get(x[0], 0),
                    reverse=True
                ):
                    percentage = (count / report['total_vulnerabilities']) * 100
                    print(f"  {level:12s}: {count:3d} ({percentage:5.1f}%)")
            
            print("=" * 60)
            
        except Exception as e:
            print(f"⚠️  Warning: Could not generate full report: {e}")
    
    # Show top critical vulnerabilities
    if args.verbose:
        print(f"\n🔴 Top 5 Highest Risk Vulnerabilities:")
        print("=" * 80)
        
        top_vulns = assessed_df.nlargest(5, 'risk_score')[
            ['cve_id', 'package_name', 'risk_score', 'risk_label']
        ]
        
        for idx, row in top_vulns.iterrows():
            print(f"  {row['cve_id']:20s} | {row['package_name']:25s} | "
                  f"{row['risk_score']:5.1f} | {row['risk_label']}")
        
        print("=" * 80)
    
    print(f"\n✨ Done! Results saved to: {output_path}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())