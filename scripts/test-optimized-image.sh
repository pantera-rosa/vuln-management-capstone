#!/bin/bash
set -e

echo "Building optimized Docker image..."
docker build -f src/backend/workflow/vuln_remediate/Dockerfile.optimized \
  -t vuln-remediate:optimized .

echo ""
echo "Image size comparison:"
echo "====================="
docker images | grep -E "REPOSITORY|vuln-remediate"

echo ""
echo "Testing if torch works (CPU-only)..."
docker run --rm vuln-remediate:optimized python3 -c "import torch; print(f'Torch version: {torch.__version__}'); print(f'CUDA available: {torch.cuda.is_available()}')"

echo ""
echo "Testing if transformers works..."
docker run --rm vuln-remediate:optimized python3 -c "import transformers; print(f'Transformers version: {transformers.__version__}')"

echo ""
echo "✅ All tests passed!"
