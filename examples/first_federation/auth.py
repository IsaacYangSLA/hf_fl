#!/usr/bin/env python3
"""Private device login and renewable credentials for the first-federation example."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt


class AuthError(Exception):
    """An intentionally non-secret diagnostic suitable for the command line."""


class OAuthError(AuthError):
    def __init__(self, code: str):
        self.code = code
        super().__init__("Identity provider rejected the request: " + code)


def https_url(url: str, issuer: str | None = None) -> str:
    if not isinstance(url, str):
        raise AuthError("An HTTPS URL is required.")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise AuthError("An HTTPS URL without credentials or fragment is required.")
    if issuer and parsed.netloc != urllib.parse.urlsplit(issuer).netloc:
        raise AuthError("Identity endpoints must use the issuer's HTTPS origin.")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuthError("Identity endpoint redirects are not accepted.")


def request_json(url: str, fields: dict | None = None, *, deadline=None) -> dict:
    https_url(url)
    body = urllib.parse.urlencode(fields).encode() if fields is not None else None
    request = urllib.request.Request(url, data=body, headers={"Accept": "application/json"})
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirect())
    timeout = 10 if deadline is None else min(10, deadline - time.monotonic())
    if timeout <= 0:
        raise AuthError("Credential renewal deadline elapsed.")
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(131073)
    except urllib.error.HTTPError as exc:
        # Do not include response bodies, URLs or server descriptions in errors.
        try:
            payload = json.loads(exc.read(16384))
            code = payload.get("error") if isinstance(payload, dict) else None
        except (ValueError, UnicodeError):
            code = None
        known = {"authorization_pending", "slow_down", "access_denied",
                 "expired_token", "invalid_grant", "invalid_client",
                 "unauthorized_client", "invalid_scope"}
        if code in known:
            raise OAuthError(code) from None
        raise AuthError("Identity provider returned HTTP " + str(exc.code)) from None
    except (OSError, urllib.error.URLError):
        raise AuthError("Identity provider could not be reached over verified HTTPS.") from None
    if len(raw) > 131072:
        raise AuthError("Identity response exceeded the allowed size.")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        raise AuthError("Identity provider returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise AuthError("Identity provider returned an invalid object.")
    return payload


def discovery(issuer: str) -> dict:
    https_url(issuer)
    if issuer.endswith("/") or urllib.parse.urlsplit(issuer).query:
        raise AuthError("Use the exact realm issuer without a trailing slash or query.")
    metadata = request_json(issuer + "/.well-known/openid-configuration")
    if metadata.get("issuer") != issuer:
        raise AuthError("Discovery issuer does not match the requested realm.")
    for field in ("token_endpoint", "jwks_uri", "device_authorization_endpoint"):
        if not isinstance(metadata.get(field), str):
            raise AuthError("The realm does not support device authorization.")
        https_url(metadata[field], issuer)
    return metadata


def validate_token(token: str, issuer: str, jwks_uri: str, *, deadline=None) -> dict:
    https_url(jwks_uri, issuer)
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or header.get("typ") != "at+jwt":
            raise AuthError("Access token must have alg RS256 and typ at+jwt.")
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id:
            raise AuthError("Access token is missing its signing key identifier.")
        keys = request_json(jwks_uri, deadline=deadline).get("keys", [])
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == key_id
                   and key.get("kty") == "RSA" and key.get("use", "sig") == "sig"
                   and key.get("alg", "RS256") == "RS256"]
        if len(matches) != 1:
            raise AuthError("Access token signing key is missing or ambiguous in the issuer JWKS.")
        key = jwt.PyJWK.from_dict(matches[0], algorithm="RS256").key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=issuer,
                            audience="exchange",
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        if (not isinstance(claims.get("scope"), str)
                or "exchange" not in claims["scope"].split()):
            raise AuthError("Access token lacks the required exchange scope.")
        if (not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 256
                or type(claims["exp"]) not in (int, float)
                or type(claims["iat"]) not in (int, float)
                or claims["exp"] <= time.time() + 2):
            raise ValueError()
        return claims
    except jwt.MissingRequiredClaimError as exc:
        required = {"exp", "iat", "iss", "aud", "sub"}
        name = exc.claim if exc.claim in required else "required"
        raise AuthError("Access token is missing the " + name + " claim.") from None
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError) as exc:
        # Exception class names are safe diagnostics; exception messages may contain
        # token or server-controlled values and must never be printed.
        raise AuthError("Access token failed Exchange signature or claim validation ("
                        + type(exc).__name__ + ").") from None


def identity(state: dict) -> dict:
    claims = validate_token(state["access_token"], state["issuer"], state["jwks_uri"])
    issuer, subject = claims["iss"], claims["sub"]
    principal = hashlib.sha256(json.dumps([issuer, subject], separators=(",", ":")).encode()).hexdigest()
    return {"issuer": issuer, "subject": subject, "principal_id": principal}


def atomic_private(path: Path, content: str) -> None:
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


@contextlib.contextmanager
def profile_lock(profile: Path):
    profile = profile.absolute()
    # Keep secrets out of symlinked directory trees.
    if any(parent.is_symlink() for parent in (profile, *profile.parents)):
        raise AuthError("The credential profile must not use symbolic links.")
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not profile.is_dir() or profile.stat().st_uid != os.getuid():
        raise AuthError("The credential profile must be a directory owned by this user.")
    os.chmod(profile, 0o700)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    fd = os.open(profile / ".lock", flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuthError("Invalid credential lock file.")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AuthError("This profile is already in use; wait or use another profile.") from None
        yield profile
    finally:
        os.close(fd)


def load_state(profile: Path) -> dict:
    path = profile / "credentials.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise AuthError("Credential state must be a private, user-owned regular file.")
            state = json.load(handle)
        required = ("issuer", "client_id", "token_endpoint", "jwks_uri",
                    "access_token", "refresh_token")
        if not isinstance(state, dict) or any(not isinstance(state.get(k), str)
                                              or not state[k] for k in required):
            raise ValueError()
        https_url(state["issuer"])
        https_url(state["token_endpoint"], state["issuer"])
        https_url(state["jwks_uri"], state["issuer"])
        return state
    except (OSError, ValueError, TypeError):
        raise AuthError("No usable private login state; run login again.") from None


def accept_tokens(profile: Path, state: dict, response: dict, *, deadline=None) -> dict:
    access = response.get("access_token")
    refresh = response.get("refresh_token", state.get("refresh_token"))
    if (not isinstance(response.get("token_type"), str)
            or response["token_type"].lower() != "bearer"
            or not isinstance(access, str) or not isinstance(refresh, str) or not refresh):
        raise AuthError("Identity provider did not issue renewable Bearer credentials.")
    claims = validate_token(access, state["issuer"], state["jwks_uri"], deadline=deadline)
    # Renewals must retain the identity enrolled in the project.
    if state.get("subject") and claims["sub"] != state["subject"]:
        raise AuthError("Refreshed credentials changed identity.")
    updated = dict(state, access_token=access, refresh_token=refresh,
                   expires_at=claims["exp"], issued_at=claims["iat"], subject=claims["sub"])
    atomic_private(profile / "credentials.json", json.dumps(updated) + "\n")
    atomic_private(profile / "access.token", access + "\n")
    return updated


def refresh(profile: Path, state: dict, *, deadline=None) -> dict:
    response = request_json(state["token_endpoint"], {
        "grant_type": "refresh_token", "client_id": state["client_id"],
        "refresh_token": state["refresh_token"]}, deadline=deadline)
    return accept_tokens(profile, state, response, deadline=deadline)


def login(profile: Path, issuer: str, client_id: str) -> None:
    metadata = discovery(issuer)
    response = request_json(metadata["device_authorization_endpoint"], {
        "client_id": client_id, "scope": "openid exchange"})
    try:
        device_code = response["device_code"]
        user_code = response["user_code"]
        verification = https_url(response["verification_uri"], issuer)
        expires = int(response["expires_in"])
        interval = int(response.get("interval", 5))
        if (not isinstance(device_code, str) or not device_code
                or not isinstance(user_code, str) or not user_code
                or not 1 <= expires <= 1800 or not 1 <= interval <= 60):
            raise ValueError()
        display = {"verification_uri": verification, "user_code": user_code, "expires_in": expires}
        if response.get("verification_uri_complete"):
            display["verification_uri_complete"] = https_url(
                response["verification_uri_complete"], issuer)
    except (KeyError, ValueError, TypeError):
        raise AuthError("Identity provider returned invalid device authorization details.") from None
    print(json.dumps(display), flush=True)
    deadline = time.monotonic() + expires
    while time.monotonic() + interval < deadline:
        time.sleep(interval)
        try:
            tokens = request_json(metadata["token_endpoint"], {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id, "device_code": device_code})
        except OAuthError as exc:
            if exc.code == "authorization_pending":
                continue
            if exc.code == "slow_down":
                interval = min(interval + 5, 65)
                continue
            raise
        state = accept_tokens(profile, {
            "issuer": issuer, "client_id": client_id,
            "token_endpoint": metadata["token_endpoint"], "jwks_uri": metadata["jwks_uri"]}, tokens)
        print(json.dumps(identity(state)), flush=True)
        return
    raise AuthError("Device authorization expired; run login again.")


def renewal_at(state: dict) -> float:
    lifetime = state["expires_at"] - state["issued_at"]
    return state["expires_at"] - min(60, max(1, lifetime / 2))


def command_environment(profile: Path, command: list[str]) -> dict:
    if not command:
        raise AuthError("run requires a command after --.")
    for word in command:
        option = word.partition("=")[0]
        # HF2L uses argparse's long-option abbreviation. Reject every token-option
        # prefix as well as its full spelling, while allowing unrelated --tokens
        # or --tokenizer settings in an existing trainer.
        token_option = (option.startswith("--") and len(option) > 2
                        and any(flag.startswith(option) for flag in ("--token", "--token-file")))
        if token_option or word.startswith(("EXCHANGE_TOKEN=", "EXCHANGE_TOKEN_FILE=")):
            raise AuthError("Token overrides are not allowed; run manages the token file.")
    environment = dict(os.environ)
    environment.pop("EXCHANGE_TOKEN", None)
    environment["EXCHANGE_TOKEN_FILE"] = str(profile / "access.token")
    return environment


def stop_child(child: subprocess.Popen) -> None:
    if child.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def run(profile: Path, command: list[str]) -> int:
    environment = command_environment(profile, command)
    state = load_state(profile)
    # Always exchange the refresh credential before exposing it to a child.
    state = refresh(profile, state)
    child = subprocess.Popen(command, env=environment, start_new_session=True)
    previous = {}
    interrupted = None

    def forward(signum, frame):
        nonlocal interrupted
        interrupted = signum
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, forward)
        next_attempt = renewal_at(state)
        retry = 1
        while child.poll() is None:
            if interrupted is not None:
                stop_child(child)
                return 128 + interrupted
            now = time.time()
            if now >= state["expires_at"] - 2:
                raise AuthError("Credentials expired; stopping the child command. Log in again.")
            if now >= next_attempt:
                try:
                    deadline = time.monotonic() + state["expires_at"] - time.time() - 2
                    state = refresh(profile, state, deadline=deadline)
                    next_attempt = renewal_at(state)
                    retry = 1
                except AuthError:
                    # Preserve valid credentials during brief outages, but never run past expiry.
                    next_attempt = min(time.time() + retry, state["expires_at"] - 2)
                    retry = min(retry * 2, 15)
                    print("Credential renewal unavailable; retrying before expiry.", file=sys.stderr)
            time.sleep(0.2)
        result = child.wait()
        return result if result >= 0 else 128 - result
    finally:
        stop_child(child)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("login", "identity", "run"):
        sub = commands.add_parser(name)
        sub.add_argument("--profile", type=Path, required=True)
        if name == "login":
            sub.add_argument("--issuer", required=True)
            sub.add_argument("--client-id", default="hf2l-cli")
        if name == "run":
            sub.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        with profile_lock(args.profile) as profile:
            if args.action == "login":
                login(profile, args.issuer, args.client_id)
            elif args.action == "identity":
                print(json.dumps(identity(load_state(profile))))
            else:
                command = args.command[1:] if args.command[:1] == ["--"] else args.command
                return run(profile, command)
    except (AuthError, OSError) as exc:
        # OSError may embed paths but never include a credential or HTTP response.
        print("Authentication error: " + (str(exc) if isinstance(exc, AuthError)
                                         else "Local credential or child process operation failed."),
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
