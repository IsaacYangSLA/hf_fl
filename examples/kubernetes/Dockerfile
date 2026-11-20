# Build from the repository root; no Git credentials or private data are copied.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG HF2L_VERSION=0.0.dev0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_HF2L=${HF2L_VERSION}
WORKDIR /opt/hf2l
COPY pyproject.toml README.md ./
COPY hf2l ./hf2l
COPY packages/exchange/pyproject.toml packages/exchange/README.md ./packages/exchange/
COPY packages/exchange/src ./packages/exchange/src
COPY examples/first_federation/model.py ./examples/first_federation/model.py
COPY examples/kubernetes ./examples/kubernetes
RUN pip install --no-cache-dir ./packages/exchange . \
    && mkdir -p /work && chown 10001:10001 /work
USER 10001:10001
CMD ["hf2l", "--help"]
