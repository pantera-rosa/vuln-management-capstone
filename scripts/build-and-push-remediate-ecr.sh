#!/bin/bash
set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
ECR_REPO_NAME="vuln-remediate"
DOCKERFILE_PATH="src/backend/workflow/vuln_remediate/Dockerfile"

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}"

echo "========================================="
echo "Building and Pushing Optimized Image"
echo "========================================="
echo "AWS Account: ${AWS_ACCOUNT_ID}"
echo "Region: ${AWS_REGION}"
echo "ECR Repository: ${ECR_REPO_NAME}"
echo "ECR URI: ${ECR_URI}"
echo "Dockerfile: ${DOCKERFILE_PATH}"
echo ""

# Login to ECR
echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build the image
echo ""
echo "Building Docker image..."
docker build -f ${DOCKERFILE_PATH} -t ${ECR_REPO_NAME}:latest .

# Tag for ECR
echo ""
echo "Tagging image for ECR..."
docker tag ${ECR_REPO_NAME}:latest ${ECR_URI}:latest

# Push to ECR
echo ""
echo "Pushing to ECR..."
docker push ${ECR_URI}:latest

# Show final image info
echo ""
echo "========================================="
echo "✅ Build and Push Complete!"
echo "========================================="
echo "Image: ${ECR_URI}:latest"
echo ""
echo "Image size comparison:"
docker images | grep -E "REPOSITORY|${ECR_REPO_NAME}"
echo ""
echo "Verify in AWS:"
aws ecr describe-images \
  --repository-name ${ECR_REPO_NAME} \
  --region ${AWS_REGION} \
  --query 'sort_by(imageDetails,& imagePushedAt)[-1].[imageTags[0], imageSizeInBytes]' \
  --output table
