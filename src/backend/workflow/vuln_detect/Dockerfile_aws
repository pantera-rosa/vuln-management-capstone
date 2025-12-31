# -----------------------------
# Build stage
# -----------------------------
FROM public.ecr.aws/lambda/python:3.13 AS build

# Install system dependencies and tools needed for vulnerability scanning
# Note: findutils is added for 'find' command used in permission fixing
RUN dnf install -y \
    git \
    wget \
    tar \
    findutils \
    && dnf clean all

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype for vulnerability scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Pre-download Grype vulnerability database during build
# This avoids the download during Lambda execution
ENV GRYPE_DB_CACHE_DIR=/grype-db
RUN mkdir -p ${GRYPE_DB_CACHE_DIR} && \
    grype db update && \
    echo "Grype database downloaded successfully" && \
    # Fix permissions - make everything readable (directories 755, files 644)
    chmod -R a+rX ${GRYPE_DB_CACHE_DIR} && \
    # List what was downloaded (for debugging)
    echo "=== Database contents ===" && \
    ls -laR ${GRYPE_DB_CACHE_DIR}

# Verify installations
RUN git --version && syft --version && grype version

# Install Poetry
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VERSION="2.0.1"
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry

# Set up project directory
WORKDIR /build
ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_NO_INTERACTION=1

# Copy Poetry files
COPY pyproject.toml poetry.lock* ./

# Create a minimal README if it doesn't exist (Poetry needs it)
RUN touch README.md

# Install Python dependencies
RUN poetry install --no-root --no-ansi

# -----------------------------
# Runtime stage
# -----------------------------
FROM public.ecr.aws/lambda/python:3.13

# Install runtime system dependencies
RUN dnf install -y \
    git \
    && dnf clean all

# Copy git, syft, and grype binaries from build stage
COPY --from=build /usr/local/bin/syft /usr/local/bin/syft
COPY --from=build /usr/local/bin/grype /usr/local/bin/grype

# Copy pre-downloaded Grype database from build stage
# Place it in /opt where Lambda can read it (read-only is fine)
COPY --from=build /grype-db /opt/grype-db

# Ensure correct permissions on database files (readable by all)
# Using chmod -R a+rX makes directories executable and files readable
RUN chmod -R a+rX /opt/grype-db && \
    echo "=== Database permissions fixed ===" && \
    ls -laR /opt/grype-db/

# Copy the virtualenv site-packages from build stage
COPY --from=build /build/.venv/lib/python3.13/site-packages/ ${LAMBDA_RUNTIME_DIR}/

# Copy application code to Lambda task root
COPY src/ ${LAMBDA_TASK_ROOT}/src/
COPY src/backend/workflow/vuln_detect/lambda_function.py ${LAMBDA_TASK_ROOT}/

# Set Grype configuration via environment variables
# CRITICAL: Disable auto-update to prevent writes to read-only filesystem
ENV GRYPE_DB_CACHE_DIR=/opt/grype-db
ENV GRYPE_DB_AUTO_UPDATE=false
ENV GRYPE_DB_VALIDATE_AGE=false
ENV XDG_CACHE_HOME=/tmp/.cache

# Verify tools are available in runtime and test database access
RUN git --version && \
    syft --version && \
    grype version && \
    echo "=== Testing Grype DB access ===" && \
    grype db status

# Set the Lambda handler
CMD ["lambda_function.lambda_handler"]