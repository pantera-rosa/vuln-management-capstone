#!/bin/bash
#set -e
# ===========================================
# AWS Batch Deployment Script
# Vulnerability Code Identification
# ===========================================
# Configuration - Set these values
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REPOSITORY="${ECR_REPOSITORY:-vuln-identify-batch}"
STACK_NAME="${STACK_NAME:-vuln-identify-batch}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
# Required parameters (must be set via environment or prompts)
S3_BUCKET="${S3_BUCKET}"
GH_TOKEN="${GH_TOKEN}"
SEMGREP_APP_TOKEN="${SEMGREP_APP_TOKEN}"
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }
echo_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# ===========================================
# Validation
# ===========================================
validate() {
    echo_step "Validating configuration..."
    
    if [ -z "$AWS_ACCOUNT_ID" ]; then
        echo_error "AWS_ACCOUNT_ID not set. Configure AWS CLI."
        exit 1
    fi
    
    if [ -z "$S3_BUCKET" ]; then
        echo_error "S3_BUCKET is required. Set it via environment variable."
        exit 1
    fi
    
    if [ -z "$GH_TOKEN" ]; then
        echo_error "GH_TOKEN is required. Set it via environment variable."
        exit 1
    fi
    
    echo_info "Configuration validated"
    echo "  AWS Account: $AWS_ACCOUNT_ID"
    echo "  Region: $AWS_REGION"
    echo "  S3 Bucket: $S3_BUCKET"
}

# ===========================================
# Build Docker Image
# ===========================================
build_image() {
    echo_step "Building Docker image..."
    
    #PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)/../../../..}"
    
    docker build -f src/backend/workflow/vuln_identify/Dockerfile_aws -t "$ECR_REPOSITORY" .
    
    echo_info "Docker image built successfully"
}

# ===========================================
# Push to ECR
# ===========================================
push_to_ecr() {
    echo_step "Pushing image to ECR..."
    
    # Create ECR repository if it doesn't exist
    if ! aws ecr describe-repositories --repository-names "$ECR_REPOSITORY" --region "$AWS_REGION" &> /dev/null; then
        echo_info "Creating ECR repository: $ECR_REPOSITORY"
        aws ecr create-repository \
            --repository-name "$ECR_REPOSITORY" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true
    fi
    
    # Authenticate with ECR
    aws ecr get-login-password --region "$AWS_REGION" | \
        docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    
    # Tag and push
    ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${IMAGE_TAG}"
    docker tag "${ECR_REPOSITORY}:${IMAGE_TAG}" "$ECR_URI"
    docker push "$ECR_URI"
    
    echo_info "Image pushed: $ECR_URI"
}

# ===========================================
# Deploy CloudFormation Stack
# ===========================================
deploy_infrastructure() {
    echo_step "Deploying CloudFormation stack..."
    
    ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${IMAGE_TAG}"
    
    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" &> /dev/null; then
        echo_info "Updating existing stack: $STACK_NAME"
        aws cloudformation update-stack \
            --stack-name "$STACK_NAME" \
            --template-body file://src/backend/workflow/vuln_identify/Cloudformation.yaml \
            --parameters \
                ParameterKey=S3BucketName,ParameterValue="$S3_BUCKET" \
                ParameterKey=GitHubToken,ParameterValue="$GH_TOKEN" \
                ParameterKey=SemgrepAppToken,ParameterValue="$SEMGREP_APP_TOKEN" \
                ParameterKey=ECRImageUri,ParameterValue="$ECR_URI" \
            --capabilities CAPABILITY_NAMED_IAM \
            --region "$AWS_REGION" || echo_warn "No updates to apply"
    else
        echo_info "Creating new stack: $STACK_NAME"
        aws cloudformation create-stack \
            --stack-name "$STACK_NAME" \
            --template-body file://src/backend/workflow/vuln_identify/Cloudformation.yaml \
            --parameters \
                ParameterKey=S3BucketName,ParameterValue="$S3_BUCKET" \
                ParameterKey=GitHubToken,ParameterValue="$GH_TOKEN" \
                ParameterKey=SemgrepAppToken,ParameterValue="$SEMGREP_APP_TOKEN" \
                ParameterKey=ECRImageUri,ParameterValue="$ECR_URI" \
            --capabilities CAPABILITY_NAMED_IAM \
            --region "$AWS_REGION"
    fi
    
    echo_info "Waiting for stack to complete (this may take 5-10 minutes)..."
    aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$AWS_REGION" 2>/dev/null || \
    aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" --region "$AWS_REGION" 2>/dev/null || true
    
    echo_info "Stack deployment complete"
}

# ===========================================
# Submit Test Job
# ===========================================
submit_job() {
    FOLDER_NAME="${1:-}"
    
    echo_step "Submitting Batch job..."
    
    JOB_NAME="vuln-identify-$(date +%Y%m%d-%H%M%S)"
    
    CMD="aws batch submit-job \
        --job-name $JOB_NAME \
        --job-queue vuln-identify-queue \
        --job-definition vuln-identify-job \
        --region $AWS_REGION"
    
    if [ -n "$FOLDER_NAME" ]; then
        CMD="$CMD --container-overrides environment=[{name=FOLDER_NAME,value=$FOLDER_NAME}]"
    fi
    
    RESPONSE=$(eval $CMD)
    JOB_ID=$(echo $RESPONSE | jq -r '.jobId')
    
    echo_info "Job submitted successfully!"
    echo "  Job Name: $JOB_NAME"
    echo "  Job ID: $JOB_ID"
    echo ""
    echo "Monitor job status:"
    echo "  aws batch describe-jobs --jobs $JOB_ID --region $AWS_REGION"
    echo ""
    echo "View logs in CloudWatch:"
    echo "  Log Group: /aws/batch/vuln-identify"
}

# ===========================================
# Check Job Status
# ===========================================
check_job_status() {
    JOB_ID="$1"
    
    if [ -z "$JOB_ID" ]; then
        echo_error "Job ID required"
        exit 1
    fi
    
    echo_step "Checking job status..."
    
    RESPONSE=$(aws batch describe-jobs --jobs "$JOB_ID" --region "$AWS_REGION")
    STATUS=$(echo $RESPONSE | jq -r '.jobs[0].status')
    
    echo_info "Job Status: $STATUS"
    
    case $STATUS in
        SUBMITTED)
            echo "  Job is waiting in queue"
            ;;
        PENDING)
            echo "  Job is pending scheduling"
            ;;
        RUNNABLE)
            echo "  Job is ready to run, waiting for resources"
            ;;
        STARTING)
            echo "  Job is starting up"
            ;;
        RUNNING)
            STARTED=$(echo $RESPONSE | jq -r '.jobs[0].startedAt')
            echo "  Started at: $(date -d @$((STARTED/1000)))"
            ;;
        SUCCEEDED)
            echo "  Job completed successfully!"
            STOPPED=$(echo $RESPONSE | jq -r '.jobs[0].stoppedAt')
            STARTED=$(echo $RESPONSE | jq -r '.jobs[0].startedAt')
            DURATION=$(( (STOPPED - STARTED) / 1000 ))
            echo "  Duration: ${DURATION} seconds"
            ;;
        FAILED)
            echo_error "Job failed!"
            REASON=$(echo $RESPONSE | jq -r '.jobs[0].statusReason')
            echo "  Reason: $REASON"
            ;;
    esac
}

# ===========================================
# Main
# ===========================================
main() {
    case "${1:-deploy}" in
        validate)
            validate
            ;;
        build)
            build_image
            ;;
        push)
            push_to_ecr
            ;;
        infrastructure)
            validate
            deploy_infrastructure
            ;;
        deploy)
            validate
            build_image
            push_to_ecr
            deploy_infrastructure
            echo_info "Deployment complete!"
            ;;
        submit)
            submit_job "${2:-}"
            ;;
        status)
            check_job_status "$2"
            ;;
        *)
            echo "AWS Batch Deployment for Vulnerability Code Identification"
            echo ""
            echo "Usage: $0 <command> [options]"
            echo ""
            echo "Commands:"
            echo "  validate       - Validate configuration"
            echo "  build          - Build Docker image"
            echo "  push           - Push image to ECR"
            echo "  infrastructure - Deploy CloudFormation stack"
            echo "  deploy         - Full deployment (build + push + infrastructure)"
            echo "  submit [folder] - Submit a Batch job (optional: specify folder)"
            echo "  status <job-id> - Check job status"
            echo ""
            echo "Environment Variables:"
            echo "  S3_BUCKET      - S3 bucket name (required)"
            echo "  GH_TOKEN       - GitHub token (required)"
            echo "  AWS_REGION     - AWS region (default: us-east-1)"
            exit 1
            ;;
    esac
}

main "$@"