# -----------------------------
# Build stage
# -----------------------------
FROM python:3.13-slim AS build
# System deps needed to build wheels that may not have prebuilt wheels
RUN apt-get update \
    && apt-get install -y \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# Install Poetry (same pattern as detect)
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VERSION="2.0.1"
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH=$POETRY_HOME/bin:$PATH
# Project layout + in-project venv (same pattern as detect)
WORKDIR /vuln_assess
ENV POETRY_VIRTUALENVS_IN_PROJECT=1
# Lockfile + pyproject first (cache-friendly)
COPY poetry.lock pyproject.toml ./
RUN poetry install --only main --no-root
# Bring in only what assess needs (plus shared utils/schemas)
# If you have more modules under vuln_assess/, copying the whole dir avoids missing imports.
COPY src/backend/workflow/vuln_assess/assessor.py ./src/backend/workflow/vuln_assess/
COPY src/backend/workflow/vuln_assess/providers.py ./src/backend/workflow/vuln_assess/
COPY src/backend/utils/df.py ./src/backend/utils/
COPY src/backend/utils/http.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
# -----------------------------
# Runtime stage
# -----------------------------
FROM python:3.13-slim AS run
# Minimal runtime deps (removed build-essential and libffi-dev - not needed at runtime)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         git \
         curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /vuln_assess
# Use the build-stage virtualenv
COPY --from=build /vuln_assess/.venv /vuln_assess/.venv
ENV PATH=/vuln_assess/.venv/bin:$PATH
# App code (mirror what was copied in the build stage)
COPY src/backend/workflow/vuln_assess/assessor.py ./src/backend/workflow/vuln_assess/
COPY src/backend/workflow/vuln_assess/providers.py ./src/backend/workflow/vuln_assess/
COPY src/backend/utils/df.py ./src/backend/utils/
COPY src/backend/utils/http.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
# If assessor.py exposes a CLI (__main__), this will work.
# If not, switch to the correct module that provides a main().
ENTRYPOINT [ "python3", "-m", "src.backend.workflow.vuln_assess.assessor"]