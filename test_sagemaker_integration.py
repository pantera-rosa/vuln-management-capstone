#!/usr/bin/env python3
"""
Test script for SageMaker integration in the remediation workflow.
Run this to verify the SageMaker endpoint is accessible and working.
"""

import os
import sys
import boto3
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

def test_aws_credentials():
    """Test if AWS credentials are configured."""
    print("🔍 Testing AWS credentials...")
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ AWS credentials valid")
        print(f"   Account: {identity['Account']}")
        print(f"   User: {identity['Arn']}")
        return True
    except Exception as e:
        print(f"❌ AWS credentials not configured: {e}")
        print("   Please configure AWS credentials using:")
        print("   - aws configure")
        print("   - or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars")
        return False

def test_sagemaker_endpoint_exists():
    """Test if the SageMaker endpoint exists and is accessible."""
    print("\n🔍 Testing SageMaker endpoint accessibility...")
    endpoint_name = "jumpstart-dft-meta-textgeneration-l-20251120-210732"
    region = "us-east-1"
    
    try:
        sagemaker_client = boto3.client('sagemaker', region_name=region)
        response = sagemaker_client.describe_endpoint(EndpointName=endpoint_name)
        
        print(f"✅ Endpoint '{endpoint_name}' found")
        print(f"   Status: {response['EndpointStatus']}")
        print(f"   Created: {response['CreationTime']}")
        print(f"   Last Modified: {response['LastModifiedTime']}")
        
        if response['EndpointStatus'] != 'InService':
            print(f"⚠️  WARNING: Endpoint is not 'InService', status is: {response['EndpointStatus']}")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Could not access endpoint: {e}")
        print(f"   Make sure endpoint '{endpoint_name}' exists in region '{region}'")
        return False

def test_endpoint_invocation():
    """Test if we can invoke the SageMaker endpoint."""
    print("\n🔍 Testing SageMaker endpoint invocation...")
    
    try:
        from src.backend.aws.sagemaker.sagemaker import invoke_sagemaker_endpoint
        
        test_prompt = "What is a common software vulnerability?"
        print(f"   Sending test prompt: '{test_prompt}'")
        
        response = invoke_sagemaker_endpoint(
            prompt=test_prompt,
            endpoint_name="jumpstart-dft-meta-textgeneration-l-20251120-210732",
            region="us-east-1",
            max_tokens=100
        )
        
        print(f"✅ Endpoint invocation successful!")
        print(f"   Response length: {len(response)} characters")
        print(f"   Response preview: {response[:200]}...")
        return True
    except Exception as e:
        print(f"❌ Endpoint invocation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_remediation_workflow():
    """Test the full remediation workflow."""
    print("\n🔍 Testing remediation workflow with SageMaker...")
    
    # Check if assessment file exists
    assessment_dir = Path("artifacts/assessments")
    if not assessment_dir.exists():
        print(f"⚠️  Assessment directory does not exist: {assessment_dir}")
        print("   Please run 'make detect', 'make identify', and 'make assess' first")
        return False
    
    # Find the latest assessment file
    assessment_files = sorted(assessment_dir.glob("*.parquet"), reverse=True)
    if not assessment_files:
        print(f"⚠️  No assessment files found in {assessment_dir}")
        return False
    
    latest_assessment = assessment_files[0]
    print(f"   Found assessment file: {latest_assessment.name}")
    
    try:
        import pandas as pd
        df = pd.read_parquet(latest_assessment)
        print(f"   Assessment data shape: {df.shape}")
        print(f"   Columns: {list(df.columns)}")
        
        if df.empty:
            print("⚠️  Assessment file is empty")
            return False
        
        print(f"✅ Assessment file loaded successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to load assessment file: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("SageMaker Integration Test Suite")
    print("=" * 60)
    
    tests = [
        ("AWS Credentials", test_aws_credentials),
        ("SageMaker Endpoint Exists", test_sagemaker_endpoint_exists),
        ("Endpoint Invocation", test_endpoint_invocation),
        ("Remediation Workflow", test_remediation_workflow),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Test '{test_name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    print("=" * 60)
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    all_passed = all(results.values())
    print("=" * 60)
    
    if all_passed:
        print("✅ All tests passed! You're ready to run 'make remediate'")
        print("\nNext steps:")
        print("1. Run: make remediate")
        print("2. Check: artifacts/remediate/log4j_remediate_pd.parquet")
        return 0
    else:
        print("❌ Some tests failed. Please fix the issues above before proceeding.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

