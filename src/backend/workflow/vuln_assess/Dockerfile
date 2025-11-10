# -----------------------------
# Build stage
# -----------------------------
FROM public.ecr.aws/lambda/python:3.13 AS build

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

# Create a minimal README if it doesn't exist
RUN touch README.md

# Install dependencies
RUN poetry install --only main --no-root --no-ansi

# -----------------------------
# Runtime stage
# -----------------------------
FROM public.ecr.aws/lambda/python:3.13

# Copy the virtualenv from build stage
COPY --from=build /build/.venv/lib/python3.13/site-packages/ ${LAMBDA_RUNTIME_DIR}/

# Copy application code to Lambda task root
COPY src/ ${LAMBDA_TASK_ROOT}/src/

# Set the handler
CMD ["src.backend.workflow.vuln_assess.lambda_function.lambda_handler"]