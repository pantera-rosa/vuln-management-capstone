# Remediation QuickStart

Your vulnerability remediation pipeline is ready to deploy!

## 🚀 Quick Setup (5 minutes)

### Option 1: Automatic (EventBridge + CodeBuild)

```bash
# See: aws/REMEDIATION_SETUP.md
# Follow steps 1-3 to enable automatic triggering
```

### Option 2: Manual Trigger

```bash
# Run remediation manually
aws codebuild start-build --project-name vuln-remediation
```

## 📊 What Happens

1. Assessment file uploaded to S3 → `assessments/`
2. EventBridge detects upload
3. CodeBuild project starts
4. Remediation runs with SageMaker endpoint
5. Results saved to S3 → `remediations/`
   - `remediation_assessment_*.parquet` (data)
   - `remediation_assessment_*.json` (human-readable)

## 🔧 Configuration

- **Buildspec**: `buildspec-remediate.yml`
- **S3 Bucket**: `vg-vuln-scan-artifacts-20251016215106`
- **SageMaker Endpoint**: `jumpstart-dft-meta-textgeneration-l-20251120-210732`
- **Region**: `us-east-1`

## 📈 Monitoring

```bash
# Watch logs
aws logs tail /aws/codebuild/vuln-remediation --follow

# Check S3 output
aws s3 ls s3://vg-vuln-scan-artifacts-20251016215106/remediations/
```

## 💰 Cost

- CodeBuild: ~$0.25-1.00 per run
- S3: negligible
- SageMaker endpoint: ~$72/month (always on)
- **Total**: ~$72/month

## 📚 Full Setup Guide

See: `aws/REMEDIATION_SETUP.md`

---

**Ready to go!** 🎉

