# Setting Up Remediate with ECR

This guide explains how to build and push the remediate Docker image to ECR for use in CodeBuild.

## Prerequisites

- AWS CLI configured with appropriate permissions
- Docker installed locally
- Access to ECR repository

## Step 1: Create ECR Repository (if it doesn't exist)

```bash
aws ecr create-repository \
    --repository-name vuln-remediate \
    --region us-east-1 \
    --image-scanning-configuration scanOnPush=true
```

## Step 2: Get ECR Login Token

```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <your-account-id>.dkr.ecr.us-east-1.amazonaws.com
```

Replace `<your-account-id>` with your AWS account ID.

## Step 3: Build the Docker Image

From the repository root:

```bash
docker build \
    -f src/backend/workflow/vuln_remediate/Dockerfile \
    -t vuln-remediate:latest \
    .
```

## Step 4: Tag the Image

```bash
docker tag vuln-remediate:latest <your-account-id>.dkr.ecr.us-east-1.amazonaws.com/vuln-remediate:latest
```

## Step 5: Push to ECR

```bash
docker push <your-account-id>.dkr.ecr.us-east-1.amazonaws.com/vuln-remediate:latest
```

## Step 6: Update CodeBuild Project

In the AWS Console:

1. Go to **CodeBuild** → Your remediate project
2. Click **Edit** → **Environment**
3. Under **Environment image**, select **Custom image**
4. Enter your ECR image URI:
   ```
   <your-account-id>.dkr.ecr.us-east-1.amazonaws.com/vuln-remediate:latest
   ```
5. Select **Privileged** if needed (for Docker-in-Docker, though not required here)
6. Save changes

## Step 7: Update Buildspec (Optional)

The buildspec has been updated to work with ECR. The `install` phase is no longer needed since dependencies are pre-installed in the image.

## Benefits

- **Faster builds**: Dependencies pre-installed (~2-3 minutes saved per build)
- **Consistency**: Same environment every time
- **Matches architecture**: Aligns with other workflows (detect, assess, identify)

## Notes

- Models are still downloaded from HuggingFace at runtime (to keep image size reasonable)
- Source code is mounted by CodeBuild at `$CODEBUILD_SRC_DIR`
- The image includes: Poetry, transformers, GitHub CLI, and all Python dependencies

## Troubleshooting

**Image too large?**
- Models are downloaded at runtime, so image should be ~1-2GB
- If it's larger, check for unnecessary files in the build

**Build fails with "module not found"?**
- Ensure all required source files are copied in the Dockerfile
- Check that `PYTHONPATH` includes `$CODEBUILD_SRC_DIR` in buildspec

**Permission errors?**
- Ensure CodeBuild service role has `ecr:GetAuthorizationToken` and `ecr:BatchGetImage` permissions

