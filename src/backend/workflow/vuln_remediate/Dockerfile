# -----------------------------
# Build stage
# -----------------------------
FROM python:3.12-slim AS build

# Install build dependencies (minimize what we install)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VERSION="2.0.1"
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && rm -rf /root/.cache
ENV PATH=$POETRY_HOME/bin:$PATH

# Set working directory
WORKDIR /vuln_remediate
ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_NO_INTERACTION=1

# Copy dependency files
COPY poetry.lock pyproject.toml ./

# Install dependencies with CPU-only PyTorch (HUGE space savings: ~2GB -> ~200MB)
# First install without torch, then install CPU-only torch
RUN poetry install --only main --no-root --no-ansi \
    && .venv/bin/pip uninstall -y torch \
    && .venv/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && find /vuln_remediate/.venv -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true \
    && find /vuln_remediate/.venv -type f -name "*.pyc" -delete

# Copy source files needed for remediation
COPY src/backend/workflow/vuln_remediate/ ./src/backend/workflow/vuln_remediate/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/utils/df.py ./src/backend/utils/
COPY src/backend/utils/llm.py ./src/backend/utils/
COPY src/backend/utils/compat.py ./src/backend/utils/
COPY src/backend/aws/sagemaker/sagemaker.py ./src/backend/aws/sagemaker/
COPY src/backend/schemas/models.py ./src/backend/schemas/
COPY scripts/run_remediation_from_build.py ./scripts/

# -----------------------------
# Runtime stage
# -----------------------------
FROM python:3.12-slim AS run

# Install runtime dependencies in a single layer with aggressive cleanup
# Removed: build-essential (not needed at runtime, saves ~200MB)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        unzip \
        wget \
        ca-certificates \
        gnupg \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip -q awscliv2.zip \
    && ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli \
    && rm -rf awscliv2.zip aws \
    && apt-get remove -y wget unzip gnupg \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /root/.cache

# Set working directory
WORKDIR /vuln_remediate

# Copy virtualenv from build stage
COPY --from=build /vuln_remediate/.venv /vuln_remediate/.venv
ENV PATH=/vuln_remediate/.venv/bin:$PATH

# Copy application code structure (CodeBuild will mount source, but this ensures imports work)
COPY --from=build /vuln_remediate/src/backend/workflow/vuln_remediate/ ./src/backend/workflow/vuln_remediate/
COPY --from=build /vuln_remediate/src/backend/utils/ ./src/backend/utils/
COPY --from=build /vuln_remediate/src/backend/aws/ ./src/backend/aws/
COPY --from=build /vuln_remediate/src/backend/schemas/ ./src/backend/schemas/
COPY --from=build /vuln_remediate/scripts/ ./scripts/

# Set default working directory (CodeBuild will override this)
WORKDIR /codebuild/output/src*

# Default entrypoint (CodeBuild will run commands from buildspec)
ENTRYPOINT ["/bin/bash"]
