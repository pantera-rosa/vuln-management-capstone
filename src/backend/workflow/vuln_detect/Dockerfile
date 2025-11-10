# Build stage - install dependencies
FROM python:3.13-slim AS build

# install build dependencies
RUN apt-get update \
    && apt-get install -y \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# install poetry
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VERSION="2.0.1"
RUN curl -sSL https://install.python-poetry.org | python3 -

# add poetry to path
ENV PATH=$POETRY_HOME/bin:$PATH

# set working directory
WORKDIR /vuln_detect
ENV POETRY_VIRTUALENVS_IN_PROJECT=1

# copy over dependency files
COPY poetry.lock pyproject.toml ./

# install dependencies (exclude tests)
RUN poetry install --only main --no-root


# Runtime stage - Lambda base image
FROM public.ecr.aws/lambda/python:3.13

# Install git using microdnf (the minimal package manager available in Lambda images)
RUN microdnf install -y git tar gzip findutils && microdnf clean all

# set working directory
WORKDIR ${LAMBDA_TASK_ROOT}

# copy over virtual environment from build stage
COPY --from=build /vuln_detect/.venv ./venv

# Download and install syft binary directly (specific version for reproducibility)
RUN curl -sSfL https://github.com/anchore/syft/releases/download/v1.17.0/syft_1.17.0_linux_amd64.tar.gz -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /tmp && \
    mv /tmp/syft /usr/local/bin/syft && \
    chmod +x /usr/local/bin/syft && \
    rm -rf /tmp/syft.tar.gz

# Download and install grype binary directly (specific version for reproducibility)
RUN curl -sSfL https://github.com/anchore/grype/releases/download/v0.84.0/grype_0.84.0_linux_amd64.tar.gz -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /tmp && \
    mv /tmp/grype /usr/local/bin/grype && \
    chmod +x /usr/local/bin/grype && \
    rm -rf /tmp/grype.tar.gz

# add paths
ENV PATH=/usr/local/bin:${LAMBDA_TASK_ROOT}/venv/bin:$PATH

# Create directory structure for source modules
RUN mkdir -p src/backend/workflow/vuln_detect src/backend/utils src/backend/schemas

# Copy source files to proper locations
COPY src/backend/workflow/vuln_detect/vuln_scan.py ./src/backend/workflow/vuln_detect/
COPY src/backend/workflow/vuln_detect/provider.py ./src/backend/workflow/vuln_detect/
COPY src/backend/workflow/vuln_detect/detector.py ./src/backend/workflow/vuln_detect/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/utils/http.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/

# Copy lambda_function.py to the root of LAMBDA_TASK_ROOT (where Lambda expects it)
COPY src/backend/workflow/vuln_detect/lambda_function.py ./lambda_function.py

# Create __init__.py files for proper module imports
RUN touch src/__init__.py \
    && touch src/backend/__init__.py \
    && touch src/backend/workflow/__init__.py \
    && touch src/backend/workflow/vuln_detect/__init__.py \
    && touch src/backend/utils/__init__.py \
    && touch src/backend/schemas/__init__.py

# Verify the structure and test imports (this will be visible in build logs)
RUN echo "=== Lambda Task Root Structure ===" && \
    ls -la && \
    echo "=== Source Structure ===" && \
    find src -type f && \
    echo "=== Testing Python imports ===" && \
    python3 -c "import sys; sys.path.insert(0, '.'); from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; print('✓ vuln_scan import successful')" && \
    python3 -c "import sys; sys.path.insert(0, '.'); from src.backend.utils.cmd import run_cmd_and_parse_output; print('✓ cmd import successful')" && \
    python3 -c "import sys; sys.path.insert(0, '.'); from src.backend.utils.http import get_json; print('✓ http import successful')"

# Set the CMD to your handler
CMD [ "lambda_function.lambda_handler" ]