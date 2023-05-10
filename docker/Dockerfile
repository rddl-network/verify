FROM --platform=linux/amd64 python:3.10-slim

RUN apt-get update && apt-get install -y curl bash python3-pip autoconf autogen libtool libffi-dev libssl-dev make swig meson cmake zsh gcc

RUN pip install --upgrade pip
RUN pip install poetry
RUN poetry self update


COPY rddl_verify /rddl_verify
COPY poetry.lock pyproject.toml ./

RUN poetry config virtualenvs.create false
RUN poetry install --no-root
RUN poetry shell

EXPOSE 8000:8000

RUN adduser --system --group nonroot
USER nonroot

CMD ["uvicorn", "rddl_verify.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "240", "--log-level=debug"]
