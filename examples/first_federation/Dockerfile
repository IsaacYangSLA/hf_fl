FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/hf2l
COPY packages/exchange /opt/hf2l/packages/exchange
COPY examples/first_federation/requirements-server.txt /opt/hf2l/requirements-server.txt
RUN pip install --no-cache-dir -r requirements-server.txt ./packages/exchange[server] \
    && useradd --uid 10001 --create-home exchange
USER exchange
CMD ["hf2l-exchange", "serve", "--host", "0.0.0.0"]
