# ⚠️ DEPRECATED - Use CodeBuild Instead

**This directory is deprecated.** For the remediation setup, please use:

📍 **See:** `aws/REMEDIATION_SETUP.md`

## Why CodeBuild Instead of Lambda?

- ✅ Simpler setup (no Docker/container issues)
- ✅ Leverages existing infrastructure you already have
- ✅ Better for long-running workloads (15+ min)
- ✅ Easier debugging and monitoring
- ✅ No cold start issues

## Architecture (New)

```
Assessment Files (S3)
        ↓
   EventBridge Rule
        ↓
   CodeBuild Project
        ↓
   SageMaker Endpoint
        ↓
Remediation Results (S3)
```

## Prerequisites

1. **AWS CLI** installed and configured
   ```bash
   aws --version
   aws configure
   ```

2. **SageMaker Endpoint** deployed
   - Endpoint Name: `jumpstart-dft-meta-textgeneration-l-20251120-210732`
   - Region: `us-east-1`

3. **S3 Bucket** with assessment files
   - Bucket: `vg-vuln-scan-artifacts-20251016215106`
   - Path: `assessments/`

4. **Project Code** packaged
   - The `src/` directory must be included in the Lambda deployment

## Quick Start

### 1. Deploy CloudFormation Stack

```bash
# Make script executable
chmod +x deploy.sh

# Deploy with defaults
./deploy.sh

# Or with custom parameters
./deploy.sh my-remediation-stack vg-vuln-scan-artifacts-20251016215106 jumpstart-dft-meta-textgeneration-l-20251120-210732
```

This will:
- ✅ Create IAM role with S3 and SageMaker permissions
- ✅ Deploy Lambda function with all code
- ✅ Set environment variables
- ✅ Configure timeout (15 minutes) and memory (3GB)

### 2. Test the Lambda Function

```bash
# Get the Lambda function name
aws lambda list-functions --query "Functions[?contains(FunctionName, 'vuln-remediation')].FunctionName" --output text

# Invoke the function
aws lambda invoke \
  --function-name vuln-remediation-pipeline \
  --payload '{}' \
  response.json

# View the response
cat response.json
```

### 3. Check Lambda Logs

```bash
# View logs in real-time
aws logs tail /aws/lambda/vuln-remediation-pipeline --follow

# Or view specific log stream
aws logs get-log-events \
  --log-group-name /aws/lambda/vuln-remediation-pipeline \
  --log-stream-name $(aws logs describe-log-streams \
    --log-group-name /aws/lambda/vuln-remediation-pipeline \
    --order-by LastEventTime \
    --descending \
    --max-items 1 \
    --query 'logStreams[0].logStreamName' \
    --output text)
```

## Optional: Configure S3 Trigger

To automatically trigger Lambda when assessment files are uploaded:

```bash
# Update account ID in s3-notification.json
sed -i 's/ACCOUNT_ID/123456789012/g' s3-notification.json

# Configure S3 notification
aws s3api put-bucket-notification-configuration \
  --bucket vg-vuln-scan-artifacts-20251016215106 \
  --notification-configuration file://s3-notification.json
```

Now assessments uploaded to `s3://vg-vuln-scan-artifacts-20251016215106/assessments/` will automatically trigger remediation!

## Outputs

The Lambda function produces:

### 1. Parquet File
- **Location**: `s3://vg-vuln-scan-artifacts-20251016215106/remediations/remediation_*.parquet`
- **Contains**: Full vulnerability records with remediation recommendations
- **Use**: Data analysis, reporting, downstream processing

### 2. JSON File
- **Location**: `s3://vg-vuln-scan-artifacts-20251016215106/remediations/remediation_*.json`
- **Contains**: Human-readable remediation suggestions
- **Use**: Developer review, PR generation

## Monitoring

### CloudWatch Metrics

```bash
# View invocation count
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=vuln-remediation-pipeline \
  --start-time $(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

### Lambda Insights

Enable X-Ray for better performance monitoring:

```bash
aws lambda update-function-configuration \
  --function-name vuln-remediation-pipeline \
  --tracing-config Mode=Active
```

## Troubleshooting

### Lambda Timeout

If remediation times out (15 min limit):

1. Increase timeout:
   ```bash
   aws cloudformation update-stack \
     --stack-name vuln-remediation-stack \
     --template-body file://remediation-template.yaml \
     --parameters ParameterKey=LambdaTimeout,ParameterValue=1800 \
     --capabilities CAPABILITY_NAMED_IAM
   ```

2. Increase memory (also increases CPU):
   ```bash
   aws cloudformation update-stack \
     --stack-name vuln-remediation-stack \
     --template-body file://remediation-template.yaml \
     --parameters ParameterKey=LambdaMemory,ParameterValue=10240 \
     --capabilities CAPABILITY_NAMED_IAM
   ```

### SageMaker Permission Issues

Verify the endpoint ARN is correct:

```bash
aws sagemaker describe-endpoint \
  --endpoint-name jumpstart-dft-meta-textgeneration-l-20251120-210732
```

### S3 Access Issues

Verify S3 bucket permissions:

```bash
aws s3 ls s3://vg-vuln-scan-artifacts-20251016215106/assessments/
```

## Updating the Stack

To update configuration or code:

```bash
# Update and keep existing resources
./deploy.sh vuln-remediation-stack

# Or manually
aws cloudformation update-stack \
  --stack-name vuln-remediation-stack \
  --template-body file://remediation-template.yaml \
  --parameters \
    ParameterKey=S3BucketName,ParameterValue=my-bucket \
    ParameterKey=SageMakerEndpoint,ParameterValue=my-endpoint \
  --capabilities CAPABILITY_NAMED_IAM
```

## Deleting the Stack

When you no longer need the Lambda function:

```bash
aws cloudformation delete-stack --stack-name vuln-remediation-stack
```

This will remove:
- Lambda function
- IAM role
- All associated resources

## Cost Estimation

**Approximate monthly costs** (based on typical usage):

- **Lambda Invocations**: ~$0.20 per 1M (Free tier: 1M free)
- **Lambda Compute**: ~$0.0000166667 per GB-second
  - 5 min execution × 3GB memory = $0.005 per execution
  - 100 executions/month ≈ $0.50
- **SageMaker Endpoint**: ~$0.10/hour (~$72/month active)
- **S3 Storage**: ~$0.023 per GB/month

**Total**: ~$73-75/month (mostly endpoint costs)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    AWS Account (654654605701)           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  S3 Bucket (vg-vuln-scan-artifacts)                    │
│  ├── /assessments/  ← Assessment files uploaded here   │
│  └── /remediations/ ← Remediation results stored here  │
│       ↓                                                  │
│       └─→ S3 Event Notification                         │
│            ↓                                            │
│  ┌────────────────────────────────────────────┐        │
│  │   Lambda Function (vuln-remediation)       │        │
│  │  ├── Runtime: Python 3.12                  │        │
│  │  ├── Memory: 3GB                           │        │
│  │  ├── Timeout: 15 min                       │        │
│  │  └── Env Vars:                             │        │
│  │      ├── S3_BUCKET                         │        │
│  │      ├── SAGEMAKER_ENDPOINT                │        │
│  │      └── AWS_REGION                        │        │
│  └────────────────────────────────────────────┘        │
│       ↓                                                  │
│  ┌────────────────────────────────────────────┐        │
│  │   SageMaker Runtime (us-east-1)            │        │
│  │   Endpoint: jumpstart-dft-meta-...         │        │
│  │   Model: Meta text-generation               │        │
│  └────────────────────────────────────────────┘        │
│       ↓                                                  │
│  Results → S3 /remediations/                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Next Steps

1. ✅ Deploy the stack
2. ✅ Test with manual invocation
3. ✅ Configure S3 triggers
4. ✅ Monitor logs and metrics
5. ✅ Integrate with CI/CD pipeline

## Support

For issues or questions:
1. Check CloudWatch Logs
2. Verify IAM permissions
3. Confirm SageMaker endpoint is running
4. Check S3 bucket access

---

**Deployed by**: CloudFormation  
**Maintained by**: Development Team  
**Last Updated**: 2025-11-26

