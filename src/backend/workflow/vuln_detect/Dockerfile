# install python 3.11 slim
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
# copy over relevant files
COPY src/backend/workflow/vuln_detect/vuln_scan.py ./src/backend/workflow/vuln_detect/
COPY src/backend/workflow/vuln_detect/provider.py ./src/backend/workflow/vuln_detect/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/utils/df.py ./src/backend/utils/
COPY src/backend/utils/http.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
COPY src/backend/workflow/vuln_detect/detector.py ./src/backend/workflow/vuln_detect/

FROM python:3.13-slim AS run
# install run dependencies
RUN apt-get update \
    && apt-get install -y git \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# set working directory
WORKDIR /vuln_detect
# copy over build environment
COPY --from=build /vuln_detect/.venv /vuln_detect/.venv
# install syft
RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin
# install grype
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
# add syft and grype to path
ENV PATH=/usr/local/bin:$PATH
# add build environment executables to path
ENV PATH=/vuln_detect/.venv/bin:$PATH
# copy over relevant files
COPY src/backend/workflow/vuln_detect/vuln_scan.py ./src/backend/workflow/vuln_detect/
COPY src/backend/workflow/vuln_detect/provider.py ./src/backend/workflow/vuln_detect/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/utils/df.py ./src/backend/utils/
COPY src/backend/utils/http.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
COPY src/backend/workflow/vuln_detect/detector.py ./src/backend/workflow/vuln_detect/
# entrypoint
ENTRYPOINT [ "python3", "-m", "src.backend.workflow.vuln_detect.detector"]