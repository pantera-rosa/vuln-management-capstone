# AWS Remediation Setup - CodeBuild + EventBridge

This guide sets up automatic remediation triggering when assessment files are uploaded to S3.

## Architecture

```
Assessment File Uploaded to S3
        ↓
  EventBridge Rule (S3 Event)
        ↓
  CodeBuild Project (buildspec-remediate.yml)
        ↓
  SageMaker Endpoint
        ↓
  Remediation Results → S3
```

## Prerequisites

- ✅ S3 bucket: `vg-vuln-scan-artifacts-20251016215106`
- ✅ CodeBuild role with S3 + SageMaker permissions
- ✅ SageMaker endpoint: `jumpstart-dft-meta-textgeneration-l-20251120-210732`
- ✅ HuggingFace token in Parameter Store: `/vuln-remediate/huggingface-token`

## Step 1: Create CodeBuild Project

```bash
aws codebuild create-project \
  --name vuln-remediation \
  --source type=S3,location=vg-vuln-scan-artifacts-20251016215106/code/vuln-code.tar.gz \
  --artifacts type=S3,location=vg-vuln-scan-artifacts-20251016215106/remediation-output \
  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_MEDIUM \
  --service-role arn:aws:iam::654654605701:role/CodeBuildRole \
  --source-version main
```

Or use the AWS Console:
1. Go to **AWS CodeBuild → Create project**
2. Name: `vuln-remediation`
3. Source: S3 (same bucket)
4. Environment: Ubuntu, Python 3.12
5. Service role: Use existing CodeBuild role
6. Buildspec: `buildspec-remediate.yml`

## Step 2: Create EventBridge Rule

```bash
# Create rule to trigger on S3 assessment uploads
aws events put-rule \
  --name s3-assessment-upload \
  --event-pattern '{
    "source": ["aws.s3"],
    "detail-type": ["Object Created"],
    "detail": {
      "bucket": {
        "name": ["vg-vuln-scan-artifacts-20251016215106"]
      },
      "object": {
        "key": [{
          "prefix": "assessments/"
        }]
      }
    }
  }' \
  --state ENABLED

# Add CodeBuild as target
aws events put-targets \
  --rule s3-assessment-upload \
  --targets "Id"="1","Arn"="arn:aws:codebuild:us-east-1:654654605701:project/vuln-remediation","RoleArn"="arn:aws:iam::654654605701:role/EventBridgeCodeBuildRole"
```

## Step 3: Grant S3 Permission to EventBridge

```bash
aws s3api put-bucket-notification-configuration \
  --bucket vg-vuln-scan-artifacts-20251016215106 \
  --notification-configuration '{
    "EventBridgeConfiguration": {}
  }'
```

## Step 4: Test

```bash
# Upload an assessment file to trigger
aws s3 cp artifacts/assessments/assessment_20251110-010444.parquet \
  s3://vg-vuln-scan-artifacts-20251016215106/assessments/test-assessment.parquet

# Check CodeBuild logs
aws codebuild batch-get-builds \
  --ids vuln-remediation:abc123 \
  --query 'builds[0].logs.cloudWatchLogs'

# Check S3 for results
aws s3 ls s3://vg-vuln-scan-artifacts-20251016215106/remediations/ --recursive
```

## Manual Trigger (No EventBridge)

If you don't want automatic triggering, manually run:

```bash
aws codebuild start-build \
  --project-name vuln-remediation \
  --source-version main
```

## Monitor Execution

```bash
# Watch CodeBuild logs
aws logs tail /aws/codebuild/vuln-remediation --follow

# Get build status
aws codebuild list-builds-for-project \
  --project-name vuln-remediation \
  --sort-order DESCENDING \
  --query 'ids[0]'
```

## Troubleshooting

### CodeBuild Times Out
- Increase timeout in project settings (default: 60 min)
- For large vulnerability sets, increase compute type to `BUILD_GENERAL1_LARGE`

### SageMaker Permission Denied
- Verify CodeBuild role has `sagemaker:InvokeEndpoint` permission
- Check endpoint name and region are correct

### S3 Upload Fails
- Verify CodeBuild role has `s3:PutObject` on the bucket
- Check S3 bucket policy allows the role

## Cost Estimation

**Monthly costs** (with automatic triggering):
- CodeBuild: ~$0.005 per build minute
  - If 10 builds/month × 5 min = 50 min = $0.25
- S3 operations: negligible
- SageMaker endpoint: ~$72/month (active)

**Total: ~$72/month** (mostly endpoint)

## Next Steps

1. ✅ Create CodeBuild project
2. ✅ Set up EventBridge rule
3. ✅ Grant S3 notifications permission
4. ✅ Test with manual build
5. ✅ Monitor first automatic trigger
6. ✅ Check S3 for remediation results

---

**Simple, leverages existing infrastructure, no Lambda hassles!** 🚀

