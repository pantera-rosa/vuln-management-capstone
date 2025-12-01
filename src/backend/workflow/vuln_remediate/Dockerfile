# -----------------------------
# Build stage
# -----------------------------
FROM python:3.12-slim AS build

# Install build dependencies
RUN apt-get update \
    && apt-get install -y \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VERSION="2.0.1"
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH=$POETRY_HOME/bin:$PATH

# Set working directory
WORKDIR /vuln_remediate
ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_NO_INTERACTION=1

# Copy dependency files
COPY poetry.lock pyproject.toml ./

# Install dependencies (including transformers)
RUN poetry install --only main --no-root --no-ansi

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

# Install runtime dependencies
RUN apt-get update \
    && apt-get install -y \
         git \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI (needed for creating issues)
RUN (type -p wget >/dev/null || (apt update && apt install wget -y)) \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    && cat $out | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && mkdir -p -m 755 /etc/apt/sources.list.d \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt update \
    && apt install gh -y

# Set working directory
WORKDIR /vuln_remediate

# Copy virtualenv from build stage
COPY --from=build /vuln_remediate/.venv /vuln_remediate/.venv
ENV PATH=/vuln_remediate/.venv/bin:$PATH

# Copy application code structure (CodeBuild will mount source, but this ensures imports work)
COPY src/backend/workflow/vuln_remediate/ ./src/backend/workflow/vuln_remediate/
COPY src/backend/utils/ ./src/backend/utils/
COPY src/backend/aws/ ./src/backend/aws/
COPY src/backend/schemas/ ./src/backend/schemas/
COPY scripts/ ./scripts/

# Set default working directory (CodeBuild will override this)
WORKDIR /codebuild/output/src*

# Default entrypoint (CodeBuild will run commands from buildspec)
ENTRYPOINT ["/bin/bash"]

