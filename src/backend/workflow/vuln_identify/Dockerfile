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
WORKDIR /vuln_identify
ENV POETRY_VIRTUALENVS_IN_PROJECT=1
# copy over dependency files
COPY poetry.lock pyproject.toml ./
# install dependencies (exclude tests)
RUN poetry install --only main --no-root
# copy over relevant files
COPY src/backend/workflow/vuln_identify/vuln_code_identify.py ./src/backend/workflow/vuln_identify/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
COPY src/backend/workflow/vuln_identify/identifier.py ./src/backend/workflow/vuln_identify/

FROM python:3.13-slim AS run
# install run dependencies
RUN apt-get update \
    && apt-get install -y git \
         curl \
         build-essential \
         libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# set working directory
WORKDIR /vuln_identify
# copy over build environment
COPY --from=build /vuln_identify/.venv /vuln_identify/.venv
# install gh cli
RUN (type -p wget >/dev/null || (apt update && apt install wget -y)) \
	&& mkdir -p -m 755 /etc/apt/keyrings \
	&& out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
	&& cat $out | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& mkdir -p -m 755 /etc/apt/sources.list.d \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
	&& apt update \
	&& apt install gh -y
# add build environment executables to path
ENV PATH=/vuln_identify/.venv/bin:$PATH
# install semgrep
RUN python3 -m pip install semgrep
# copy over relevant files
COPY src/backend/workflow/vuln_identify/vuln_code_identify.py ./src/backend/workflow/vuln_identify/
COPY src/backend/utils/cmd.py ./src/backend/utils/
COPY src/backend/schemas/models.py ./src/backend/schemas/
COPY src/backend/workflow/vuln_identify/identifier.py ./src/backend/workflow/vuln_identify/
# entrypoint
ENTRYPOINT [ "python3", "-m", "src.backend.workflow.vuln_identify.identifier"]