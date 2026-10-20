#!/usr/bin/env python3
"""Org S's portable, persistent first-federation service lifecycle.

Only this helper reads private operator configuration. It never prints passwords
or tokens. Use --runtime-dir outside the checkout on real deployments.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
from urllib import error, parse, request

HERE = Path(__file__).resolve().parent
DEFAULT_RUNTIME = HERE / ".runtime"
ACCOUNTS = ("bootstrap-admin", "owner", "alice", "bob")
CLIENT_ID = "hf2l-cli"
REALM = "hf2l"


def private_write(path, content, *, public=False):
    """Replace files atomically, with restrictive permissions before writing."""
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)
    os.chmod(temporary, 0o644 if public else 0o600)
    temporary.replace(path)


def system_ca_file():
    default = ssl.get_default_verify_paths()
    candidates = [os.environ.get("SSL_CERT_FILE"), default.cafile,
                  "/etc/ssl/certs/ca-certificates.crt",
                  "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            try:
                ssl.create_default_context(cafile=candidate)
                return Path(candidate)
            except (OSError, ssl.SSLError):
                continue
    raise ValueError("Install the OS CA certificate bundle before initialization")


def write_json(path, value):
    private_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_json(path):
    return json.loads(Path(path).read_text())


def validate_host(value):
    if len(value) > 253 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value
    ) or "." not in value or any(
        not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
        for part in value.split(".")
    ):
        raise ValueError("Use a lowercase fully qualified DNS hostname")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Use a DNS hostname, not an IP address")


def https_url(host, port):
    return "https://" + host + ("" if port == 443 else ":" + str(port))


def principal_id(issuer, subject):
    value = json.dumps([issuer, subject], separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def realm_document(accounts, token_seconds):
    """Keycloak representation; actual subjects are queried after import."""
    return {
        "realm": REALM, "enabled": True,
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False, "sslRequired": "external",
        "defaultSignatureAlgorithm": "RS256",
        "accessTokenLifespan": token_seconds,
        "ssoSessionIdleTimeout": 28800, "ssoSessionMaxLifespan": 28800,
        "oauth2DeviceCodeLifespan": 600, "oauth2DevicePollingInterval": 5,
        "clientScopes": [{
            "name": "basic", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false",
                           "display.on.consent.screen": "false"},
            "protocolMappers": [{
                "name": "subject", "protocol": "openid-connect",
                "protocolMapper": "oidc-sub-mapper",
                "config": {"access.token.claim": "true",
                           "introspection.token.claim": "true"},
            }],
        }, {
            "name": "exchange", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "true"},
            "protocolMappers": [{
                "name": "exchange-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": "exchange",
                           "id.token.claim": "false", "access.token.claim": "true",
                           "introspection.token.claim": "true"},
            }],
        }],
        "clients": [{
            "clientId": CLIENT_ID, "name": "HF2L command line",
            "protocol": "openid-connect", "enabled": True,
            "publicClient": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
            "serviceAccountsEnabled": False,
            "attributes": {
                "oauth2.device.authorization.grant.enabled": "true",
                "access.token.header.type.rfc9068": "true",
                "access.token.signed.response.alg": "RS256",
            },
            "defaultClientScopes": ["basic", "exchange"],
        }],
        "users": [user_document(name, accounts["accounts"][name]["password"])
                  for name in ACCOUNTS],
    }


def user_document(name, password):
    return {
        "username": name, "enabled": True, "emailVerified": True,
        "email": name + "@example.invalid", "firstName": name,
        "lastName": "First Federation", "requiredActions": [],
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }


def render_environment(runtime, config, accounts, admin_subject=""):
    prefix = {
        "HF2L_PROJECT_NAME": config["project_name"],
        "HF2L_RUNTIME_DIR": str(runtime),
        "HF2L_EXCHANGE_HOST": config["exchange_host"],
        "HF2L_AUTH_HOST": config["auth_host"],
        "HF2L_OBJECTS_HOST": config["objects_host"],
        "HF2L_HTTP_PORT": str(config["http_port"]),
        "HF2L_HTTPS_PORT": str(config["https_port"]),
        "HF2L_BIND_ADDRESS": config["bind_address"],
        "HF2L_NETWORK_SUBNET": config["network_subnet"],
        "HF2L_PROXY_IP": config["proxy_ip"],
        "HF2L_AUTH_URL": config["auth_url"],
        "HF2L_POSTGRES_PASSWORD": accounts["postgres_password"],
        "HF2L_KEYCLOAK_DB_PASSWORD": accounts["keycloak_db_password"],
        "HF2L_KEYCLOAK_ADMIN_PASSWORD": accounts["keycloak_admin"]["password"],
        "HF2L_MINIO_USER": accounts["minio_user"],
        "HF2L_MINIO_PASSWORD": accounts["minio_password"],
    }
    # json quoted strings are accepted by Compose dotenv; init disallows '$'
    # and newlines in the only free-form path to prevent interpolation.
    private_write(runtime / "compose.env", "".join(
        key + "=" + json.dumps(value) + "\n" for key, value in prefix.items()))
    values = {
        "EXCHANGE_DATABASE_URL": "postgresql+psycopg://exchange:" +
            accounts["exchange_db_password"] + "@postgres:5432/exchange",
        "EXCHANGE_ISSUER": config["issuer"],
        "EXCHANGE_AUDIENCE": "exchange",
        "EXCHANGE_JWKS_URL": config["issuer"] + "/protocol/openid-connect/certs",
        "EXCHANGE_ADMIN_SUBJECT": admin_subject,
        "EXCHANGE_S3_ENDPOINT": config["objects_url"],
        "EXCHANGE_S3_PUBLIC_ENDPOINT": config["objects_url"],
        "EXCHANGE_S3_BUCKET": "hf2l-first-federation",
        "EXCHANGE_S3_REGION": "us-east-1",
        "EXCHANGE_S3_ACCESS_KEY": accounts["minio_user"],
        "EXCHANGE_S3_SECRET_KEY": accounts["minio_password"],
        "SSL_CERT_FILE": "/run/hf2l/service-ca.crt",
        "AWS_CA_BUNDLE": "/run/hf2l/service-ca.crt",
        "NO_PROXY": config["exchange_host"] + "," + config["auth_host"] + "," +
            config["objects_host"] + ",localhost,127.0.0.1",
    }
    private_write(runtime / "exchange.env", "".join(
        key + "=" + value + "\n" for key, value in values.items()))


def initialize(args, runtime):
    if runtime.exists() and any(runtime.iterdir()):
        raise ValueError("Runtime directory is not empty; reuse it with bootstrap/start")
    if any(character in str(runtime) for character in "$\r\n"):
        raise ValueError("Runtime directory must not contain '$' or newlines")
    hosts = [validate_host(value) for value in
             (args.exchange_host, args.auth_host, args.objects_host)]
    if len(set(hosts)) != 3:
        raise ValueError("Exchange, identity, and object services need three distinct hostnames")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,40}", args.project_name):
        raise ValueError("Use a short lowercase Compose project name")
    if not 1 <= args.http_port <= 65535 or not 1 <= args.https_port <= 65535 \
            or args.http_port == args.https_port:
        raise ValueError("HTTP and HTTPS ports must be distinct values in 1..65535")
    if not 15 <= args.access_token_seconds <= 3600:
        raise ValueError("Access-token lifetime must be 15..3600 seconds")
    network = ipaddress.ip_network(args.network_subnet)
    if network.version != 4 or network.prefixlen != 24 or not network.is_private:
        raise ValueError("Network subnet must be a private IPv4 /24")
    ipaddress.ip_address(args.bind_address)
    ca_content = system_ca_file().read_text()
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(runtime, 0o700)
    config = {
        "format": 1, "project_name": args.project_name, "tls": args.tls,
        "exchange_host": hosts[0], "auth_host": hosts[1], "objects_host": hosts[2],
        "https_port": args.https_port, "http_port": args.http_port,
        "bind_address": args.bind_address, "network_subnet": str(network),
        "proxy_ip": str(network.broadcast_address - 1),
        "access_token_seconds": args.access_token_seconds,
        "client_id": CLIENT_ID,
    }
    for kind in ("exchange", "auth", "objects"):
        config[kind + "_url"] = https_url(config[kind + "_host"], args.https_port)
    config["issuer"] = config["auth_url"] + "/realms/" + REALM
    password = lambda: secrets.token_hex(24)
    accounts = {
        "keycloak_admin": {"username": "bootstrap-admin", "password": password()},
        "accounts": {name: {"username": name, "password": password()} for name in ACCOUNTS},
        "postgres_password": password(), "exchange_db_password": password(),
        "keycloak_db_password": password(),
        "minio_user": "hf2l" + secrets.token_hex(8), "minio_password": password(),
    }
    write_json(runtime / "config.json", config)
    write_json(runtime / "accounts.json", accounts)
    render_environment(runtime, config, accounts)
    statements = []
    for name in ("exchange", "keycloak"):
        # Secrets are hexadecimal, generated above, and never operator SQL input.
        secret = accounts[name + "_db_password"]
        statements.extend([
            "SELECT 'CREATE USER " + name + " WITH PASSWORD ''" + secret +
            "''' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '" + name + "') \\gexec",
            "SELECT 'CREATE DATABASE " + name + " OWNER " + name +
            "' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '" + name + "') \\gexec",
        ])
    private_write(runtime / "db-init.sql", "\n".join(statements) + "\n")
    private_write(runtime / "tls.conf", "tls internal\n" if args.tls == "internal" else "# Public ACME certificates\n")
    # Placeholder makes the bind mount a file before the first service is run.
    private_write(runtime / "service-ca.crt", ca_content, public=True)
    print("Private runtime initialized:", runtime)
    print("Next: configure DNS, then run bootstrap with this same --runtime-dir.")


class Stack:
    def __init__(self, runtime):
        self.runtime = runtime
        self.config = load_json(runtime / "config.json")
        self.accounts = load_json(runtime / "accounts.json")
        self.docker = self._docker_command()
        self.base = self.docker + ["compose", "--env-file", str(runtime / "compose.env"),
                                  "--project-name", self.config["project_name"],
                                  "--file", str(HERE / "compose.yaml")]

    @staticmethod
    def _docker_command():
        for command in (["docker"], ["sudo", "-n", "docker"]):
            try:
                result = subprocess.run(command + ["info", "--format", "{{.ServerVersion}}"],
                                        capture_output=True, check=False, timeout=20)
                if result.returncode == 0:
                    return command
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise ValueError("Docker is unavailable; install Docker/Compose and authorize its use")

    def compose(self, *args, capture=False, input_text=None):
        return subprocess.run(self.base + list(args), check=True,
                              text=True, capture_output=capture, input=input_text)

    def docker_run(self, *args, capture=False):
        return subprocess.run(self.docker + list(args), check=True, text=True,
                              capture_output=capture)

    def context(self):
        return ssl.create_default_context(cafile=str(self.runtime / "service-ca.crt"))

    def http(self, url, *, data=None, token=None, method=None, form=False):
        headers = {}
        body = None
        if data is not None:
            body = (parse.urlencode(data).encode() if form else json.dumps(data).encode())
            headers["Content-Type"] = ("application/x-www-form-urlencoded" if form else "application/json")
        if token:
            headers["Authorization"] = "Bearer " + token
        req = request.Request(url, data=body, headers=headers, method=method)
        # Do not route private service hostnames through inherited HTTP proxies.
        opener = request.build_opener(request.ProxyHandler({}),
                                      request.HTTPSHandler(context=self.context()))
        with opener.open(req, timeout=15) as response:
            content = response.read()
            return json.loads(content) if content else None

    def wait_http(self, url, seconds=180):
        deadline = time.monotonic() + seconds
        while True:
            try:
                return self.http(url)
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise ValueError("Service did not become ready: " + url) from None
                time.sleep(2)

    def start_dependencies(self):
        self.compose("up", "-d", "postgres", "minio", "caddy")
        deadline = time.monotonic() + 120
        while True:
            try:
                self.compose("exec", "-T", "postgres", "pg_isready", "-U", "postgres", capture=True)
                break
            except subprocess.CalledProcessError:
                if time.monotonic() >= deadline:
                    raise ValueError("PostgreSQL did not become ready") from None
                time.sleep(2)
        # Keep secret SQL mode 0600 on the host. Feed it over stdin instead of
        # exposing a world-readable bind mount to the PostgreSQL service UID.
        self.compose("exec", "-T", "--user", "postgres", "postgres", "psql",
                     "-U", "postgres", "--set=ON_ERROR_STOP=1",
                     input_text=(self.runtime / "db-init.sql").read_text())
        self.compose("up", "-d", "keycloak")
        if self.config["tls"] == "internal":
            container = self.compose("ps", "-q", "caddy", capture=True).stdout.strip()
            deadline = time.monotonic() + 60
            while True:
                result = subprocess.run(self.docker + ["exec", container,
                    "cat", "/data/caddy/pki/authorities/local/root.crt"],
                    capture_output=True, text=True)
                if result.returncode == 0:
                    private_write(self.runtime / "service-ca.crt", result.stdout, public=True)
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("Caddy did not generate its private test CA")
                time.sleep(1)
        self.wait_http(self.config["auth_url"] + "/realms/master/.well-known/openid-configuration")

    def reconcile_scopes(self, admin_url, token, client_id, desired_scopes):
        # Supplying custom realm scopes suppresses Keycloak's default "basic"
        # scope. Reconcile both imports and existing installations explicitly.
        scopes_url = admin_url + "/client-scopes"
        for desired in desired_scopes:
            scopes = self.http(scopes_url, token=token)
            matches = [item for item in scopes if item["name"] == desired["name"]]
            if not matches:
                self.http(scopes_url, token=token, data=desired)
                scopes = self.http(scopes_url, token=token)
                matches = [item for item in scopes if item["name"] == desired["name"]]
            if len(matches) != 1:
                raise ValueError("Expected exactly one managed OIDC client scope")
            scope_id = matches[0]["id"]
            scope_url = scopes_url + "/" + scope_id
            properties = {key: value for key, value in desired.items()
                          if key != "protocolMappers"}
            self.http(scope_url, token=token, method="PUT", data=properties)
            mapper_url = scope_url + "/protocol-mappers/models"
            mappers = self.http(mapper_url, token=token)
            for expected in desired.get("protocolMappers", []):
                found = [item for item in mappers if item["name"] == expected["name"]]
                if len(found) > 1:
                    raise ValueError("Duplicate managed OIDC protocol mapper")
                if found:
                    self.http(mapper_url + "/" + found[0]["id"], token=token,
                              method="PUT", data=dict(expected, id=found[0]["id"]))
                else:
                    self.http(mapper_url, token=token, data=expected)
            self.http(admin_url + "/clients/" + client_id +
                      "/default-client-scopes/" + scope_id, token=token, method="PUT")

    def bootstrap_identity(self):
        auth_url = self.config["auth_url"]
        master = auth_url + "/realms/master/protocol/openid-connect/token"
        token = self.http(master, data={
            "grant_type": "password", "client_id": "admin-cli",
            "username": self.accounts["keycloak_admin"]["username"],
            "password": self.accounts["keycloak_admin"]["password"],
        }, form=True)["access_token"]
        admin_url = auth_url + "/admin/realms/" + REALM
        document = realm_document(self.accounts, self.config["access_token_seconds"])
        try:
            self.http(admin_url, token=token)
        except error.HTTPError as exc:
            if exc.code != 404:
                raise
            self.http(auth_url + "/admin/realms", token=token, data=document)
        # Reconcile client/realm settings on repeat bootstrap without changing passwords.
        self.http(admin_url, token=token, method="PUT", data={
            "accessTokenLifespan": self.config["access_token_seconds"],
            "ssoSessionIdleTimeout": 28800, "ssoSessionMaxLifespan": 28800,
            "defaultSignatureAlgorithm": "RS256",
        })
        clients = self.http(admin_url + "/clients?" + parse.urlencode({"clientId": CLIENT_ID}), token=token)
        if len(clients) != 1:
            raise ValueError("Expected exactly one tutorial OIDC client")
        self.http(admin_url + "/clients/" + clients[0]["id"], token=token,
                  method="PUT", data=document["clients"][0])
        self.reconcile_scopes(admin_url, token, clients[0]["id"], document["clientScopes"])
        identities = {"issuer": self.config["issuer"], "client_id": CLIENT_ID, "accounts": {}}
        for name in ACCOUNTS:
            lookup = admin_url + "/users?" + parse.urlencode({"username": name, "exact": "true"})
            users = self.http(lookup, token=token)
            if not users:
                self.http(admin_url + "/users", token=token,
                          data=user_document(name, self.accounts["accounts"][name]["password"]))
                users = self.http(lookup, token=token)
            if len(users) != 1 or not users[0]["enabled"] or users[0]["username"] != name:
                raise ValueError("Expected exactly one enabled Keycloak user: " + name)
            subject = users[0]["id"]
            identities["accounts"][name] = {
                "username": name, "subject": subject,
                "principal_id": principal_id(self.config["issuer"], subject),
            }
        write_json(self.runtime / "identities.json", identities)
        render_environment(self.runtime, self.config, self.accounts,
                           identities["accounts"]["bootstrap-admin"]["subject"])

    def initialize_storage(self):
        code = """
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from hf2l_exchange.config import StorageSettings
s=StorageSettings.from_env()
client=boto3.client('s3',endpoint_url=s.endpoint,aws_access_key_id=s.access_key,
 aws_secret_access_key=s.secret_key,region_name=s.region,
 config=Config(signature_version='s3v4',s3={'addressing_style':'path'}))
try:
 client.head_bucket(Bucket=s.bucket)
except ClientError as exc:
 if exc.response['ResponseMetadata']['HTTPStatusCode'] != 404: raise
 client.create_bucket(Bucket=s.bucket)
client.put_bucket_versioning(Bucket=s.bucket,VersioningConfiguration={'Status':'Enabled'})
try:
 client.delete_bucket_policy(Bucket=s.bucket)
except ClientError as exc:
 if exc.response.get('Error',{}).get('Code') not in ('NoSuchBucketPolicy','NoSuchPolicy'): raise
print('Private versioned bucket ready')
"""
        self.compose("run", "--rm", "--no-deps", "exchange-api", "python", "-c", code)

    def record_release(self):
        source = subprocess.run(["git", "-C", str(HERE), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=False).stdout.strip()
        root_result = subprocess.run(["git", "-C", str(HERE), "rev-parse", "--show-toplevel"],
                                     capture_output=True, text=True, check=True)
        source_root = Path(root_result.stdout.strip())
        paths = subprocess.run(["git", "-C", str(source_root), "ls-files", "-z",
                                "--cached", "--others", "--exclude-standard"],
                               capture_output=True, check=True).stdout.split(bytes([0]))
        source_files = {}
        for raw in sorted(set(paths)):
            if not raw:
                continue
            relative = os.fsdecode(raw)
            path = source_root / relative
            if path.is_symlink():
                data = b"symlink:" + os.fsencode(os.readlink(path))
            elif path.is_file():
                data = path.read_bytes()
            else:
                source_files[relative] = None
                continue
            source_files[relative] = hashlib.sha256(data).hexdigest()
        manifest = json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()
        dirty = subprocess.run(["git", "-C", str(source_root), "status", "--porcelain"],
                               capture_output=True, check=True).stdout
        images_output = self.compose("images", "--format", "json", capture=True).stdout
        try:
            images = json.loads(images_output)
        except json.JSONDecodeError:
            images = [json.loads(line) for line in images_output.splitlines() if line.strip()]
        dependencies = self.compose("run", "--rm", "--no-deps", "exchange-api",
                                    "python", "-m", "pip", "freeze", capture=True).stdout.splitlines()
        write_json(self.runtime / "release.json", {
            "source_revision": source, "source_dirty": bool(dirty),
            "source_tree_sha256": hashlib.sha256(manifest).hexdigest(),
            "source_files": source_files, "images": images,
            "server_dependencies": dependencies,
        })

    def bootstrap(self):
        self.compose("build", "exchange-api", "minio")
        self.start_dependencies()
        self.bootstrap_identity()
        self.compose("run", "--rm", "--no-deps", "exchange-api", "hf2l-exchange", "init-db")
        self.initialize_storage()
        self.compose("up", "-d", "exchange-api", "exchange-worker")
        self.status()
        self.record_release()
        print("Bootstrap complete. Credentials:", self.runtime / "accounts.json")
        print("Verified account identities:", self.runtime / "identities.json")

    def start(self):
        if not (self.runtime / "identities.json").is_file():
            raise ValueError("Run bootstrap before start")
        self.start_dependencies()
        self.compose("up", "-d", "exchange-api", "exchange-worker")
        self.status()

    def status(self):
        discovery = self.wait_http(self.config["issuer"] + "/.well-known/openid-configuration", seconds=60)
        if discovery.get("issuer") != self.config["issuer"]:
            raise ValueError("Identity provider returned a different issuer")
        self.wait_http(self.config["objects_url"] + "/minio/health/ready", seconds=60)
        # /ready probes both the exact database schema and versioned S3 storage.
        self.wait_http(self.config["exchange_url"] + "/ready", seconds=90)
        self.compose("exec", "-T", "exchange-worker", "hf2l-exchange", "check-db")
        self.compose("exec", "-T", "exchange-worker", "hf2l-exchange", "check-storage")
        state = self.compose("ps", "--format", "json", capture=True).stdout
        try:
            rows = json.loads(state)
            rows = rows if isinstance(rows, list) else [rows]
        except json.JSONDecodeError:
            rows = [json.loads(line) for line in state.splitlines() if line.strip()]
        required = {"postgres", "minio", "keycloak", "caddy", "exchange-api", "exchange-worker"}
        running = {row["Service"] for row in rows if row.get("State") == "running"}
        if not required <= running:
            raise ValueError("Some required service containers are not running")
        print("All six services are running; OIDC, schema, and versioned storage probes passed.")
        print("Exchange:", self.config["exchange_url"])
        print("Issuer:", self.config["issuer"])

    def reset(self, confirmed):
        if not confirmed:
            raise ValueError("Destructive reset requires --confirm-delete-data")
        self.compose("down", "--volumes", "--remove-orphans")
        # Delete only the explicitly selected private runtime directory.
        shutil.rmtree(self.runtime)
        print("Owned service data and private runtime removed.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, default=DEFAULT_RUNTIME)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create private configuration; starts no services")
    init.add_argument("--exchange-host", required=True)
    init.add_argument("--auth-host", required=True)
    init.add_argument("--objects-host", required=True)
    init.add_argument("--https-port", type=int, default=443)
    init.add_argument("--http-port", type=int, default=80)
    init.add_argument("--bind-address", default="0.0.0.0")
    init.add_argument("--network-subnet", default="172.30.75.0/24")
    init.add_argument("--project-name", default="hf2l-first-federation")
    init.add_argument("--tls", choices=("public", "internal"), default="public")
    init.add_argument("--access-token-seconds", type=int, default=300,
                      help="OIDC token lifetime; short values are for renewal verification")
    for command in ("bootstrap", "start", "status", "stop"):
        commands.add_parser(command)
    reset = commands.add_parser("reset", help="Delete this stack's volumes AND private configuration")
    reset.add_argument("--confirm-delete-data", action="store_true")
    args = parser.parse_args(argv)
    runtime = args.runtime_dir.expanduser().resolve()
    try:
        if args.command == "init":
            initialize(args, runtime)
        else:
            stack = Stack(runtime)
            if args.command == "reset":
                stack.reset(args.confirm_delete_data)
            elif args.command == "stop":
                stack.compose("stop")
                print("All owned services stopped. Persistent data is retained.")
            else:
                getattr(stack, args.command)()
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # urllib exceptions can include request details. Never print their body,
        # tokens, private configuration, or expanded environment.
        print("Stack operation failed (" + type(exc).__name__ +
              "). Check configuration, DNS/TLS and owned container logs.", file=sys.stderr)
        if isinstance(exc, ValueError):
            print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
