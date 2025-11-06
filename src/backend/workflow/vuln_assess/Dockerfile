# Use AWS Lambda Python base image
FROM public.ecr.aws/lambda/python:3.13

# Install dependencies
# Copy requirements first for better caching
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ${LAMBDA_TASK_ROOT}/src/

# Set the CMD to your handler
CMD ["src.backend.workflow.vuln_assess.lambda_function.lambda_handler"]