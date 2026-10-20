#!/usr/bin/env python3
"""Qualify the first federation against its real, privately configured Compose stack.

Run with the client environment's Python. Playwright and a Chromium installation
are qualification tools only; neither belongs in participant installations.
This program never resets volumes or changes DNS/system trust.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Private directories must not be symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def last_json(output):
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("Command did not emit a JSON object")


def redact(value, secrets=()):
    result = str(value)
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    result = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
                    "[REDACTED JWT]", result)
    return result


def clean_environment(home, ca=None, endpoint=None):
    result = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    if ca:
        result.update(SSL_CERT_FILE=str(ca), REQUESTS_CA_BUNDLE=str(ca), AWS_CA_BUNDLE=str(ca))
    if endpoint:
        result["EXCHANGE_ENDPOINT"] = endpoint
    return result


def stop_process(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


def expect_denied(call, statuses=(401, 403, 404)):
    try:
        call()
    except Exception as error:
        if getattr(error, "status", None) in statuses:
            return getattr(error, "status")
        raise
    raise AssertionError("An unauthorized request unexpectedly succeeded")


def weighted_checkpoint(aggregate, alice, bob):
    """Independent numeric oracle, deliberately separate from the model helper."""
    import numpy as np
    from safetensors.numpy import load_file
    combined = load_file(str(Path(aggregate) / "model.safetensors"))
    left = load_file(str(Path(alice) / "model.safetensors"))
    right = load_file(str(Path(bob) / "model.safetensors"))
    if set(combined) != set(left) or set(left) != set(right):
        raise AssertionError("Aggregate tensor names differ from submitted checkpoints")
    differences = {}
    for name in combined:
        if left[name].shape != right[name].shape or combined[name].shape != left[name].shape:
            raise AssertionError("Aggregate tensor shape changed")
        expected = (left[name].astype("float64") * 0.4 +
                    right[name].astype("float64") * 0.6).astype(left[name].dtype)
        np.testing.assert_allclose(combined[name], expected, rtol=2e-6, atol=2e-7)
        if not np.isfinite(combined[name]).all():
            raise AssertionError("Aggregate contains nonfinite values")
        differences[name] = float(np.max(np.abs(combined[name] - expected)))
    return differences


class Verification:
    def __init__(self, args):
        self.args = args
        self.runtime = Path(args.runtime_dir).resolve()
        try:
            self.runtime.relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise ValueError("Private verification state must be outside the source checkout")
        private_directory(self.runtime)
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        self.evidence = private_directory(self.runtime.parent / (self.runtime.name + "-verification") / self.run_id)
        self.python = str(Path(args.python).expanduser().absolute())
        self.hf2l = str(Path(self.python).parent / "hf2l")
        self.processes = []
        self.checks = []
        self.secrets = []
        self.config = {}
        self.ca = None
        self.actor_root = private_directory(self.evidence / "actors")
        self.stack_env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.source_revision = self.command(["git", "rev-parse", "HEAD"], env=self.stack_env).strip()
        self.source_status = self.command(["git", "status", "--porcelain=v1"], env=self.stack_env).splitlines()
        self.config_path = self.runtime / "config.json"
        self.endpoint = None

    def command(self, args, *, actor=None, env=None, fail=False, expected_error=None, timeout=300):
        if env is None:
            env = self.actor_environment(actor) if actor else self.stack_env
        completed = subprocess.run([str(item) for item in args], cwd=ROOT,
                                   env=env, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=timeout)
        log = self.evidence / ("%03d-command.log" % len(list(self.evidence.glob("*-command.log"))))
        log.write_text(redact(completed.stdout, self.secrets))
        log.chmod(0o600)
        if fail:
            if completed.returncode == 0:
                raise AssertionError("Expected command rejection: " + str(args[0]))
            if expected_error and expected_error not in completed.stdout:
                raise AssertionError("Command failed for a different reason; inspect " + str(log))
        elif completed.returncode:
            raise RuntimeError("Command failed; inspect private evidence " + str(log))
        return completed.stdout

    def stack(self, action, *extra):
        return self.command([self.python, HERE / "stack.py", "--runtime-dir", self.runtime,
                             action, *extra], timeout=1200)

    def load_configuration(self):
        self.config = json.loads(self.config_path.read_text())
        self.ca = self.runtime / "service-ca.crt"
        if not self.ca.is_file():
            raise RuntimeError("Internal HTTPS qualification requires the generated public service CA")
        endpoints = self.config.get("endpoints", {})
        os.environ.update(SSL_CERT_FILE=str(self.ca), AWS_CA_BUNDLE=str(self.ca))
        self.endpoint = endpoints.get("exchange_url") or self.config.get("exchange_url")
        self.issuer = endpoints.get("issuer") or self.config.get("issuer")
        if not self.endpoint or not self.issuer:
            raise RuntimeError("Stack config must expose exchange endpoint and issuer")
        self.accounts = json.loads((self.runtime / "accounts.json").read_text())["accounts"]
        for account in self.accounts.values():
            self.secrets.append(account["password"])
        self.identities = self.runtime / "identities.json"
        self.client_id = json.loads(self.identities.read_text()).get("client_id", "hf2l-cli")

    def actor_directory(self, actor):
        return private_directory(self.actor_root / actor)

    def profile(self, actor):
        return self.actor_directory(actor) / "authentication"

    def actor_environment(self, actor):
        return clean_environment(self.actor_directory(actor), self.ca, self.endpoint)

    def authenticated(self, actor, args, **options):
        return self.command([self.python, HERE / "auth.py", "run", "--profile",
                             self.profile(actor), "--", *args], actor=actor, **options)

    def app(self, actor, *args, **options):
        return self.authenticated(actor, [self.hf2l, *args, "--backend", "exchange"], **options)

    def project(self, actor, action, *args, **options):
        return self.authenticated(actor, [self.python, HERE / "project.py", action,
                                         "--state", self.project_state, *args], **options)

    def record(self, name, **details):
        self.checks.append({"check": name, "status": "passed", **details})
        print(json.dumps({"check": name, "status": "passed"}), flush=True)
        self.persist()

    def persist(self, failure=None):
        result = {
            "run_id": self.run_id, "stage": self.args.stage,
            "source_revision": self.source_revision, "source_status": self.source_status,
            "checks": self.checks, "qualification": "private DNS and trusted test CA; not public ACME",
        }
        if failure:
            result["failure"] = redact(failure, self.secrets)
        save_json(self.evidence / "summary.json", result)

    def bootstrap(self):
        if self.config_path.exists():
            raise RuntimeError("Bootstrap requires a new private runtime directory; use workflow or restart for an existing stack")
        self.stack("init", "--exchange-host", self.args.exchange_host,
                   "--auth-host", self.args.auth_host, "--objects-host", self.args.objects_host,
                   "--https-port", str(self.args.https_port), "--http-port", str(self.args.http_port),
                   "--project-name", self.args.project_name or "hf2l-example-" + uuid.uuid4().hex[:10],
                   "--tls", "internal", "--access-token-seconds", "30", "--bind-address", "127.0.0.1")
        self.stack("bootstrap")
        self.load_configuration()
        self.record("real-compose-stack-bootstrap")

    def login(self, actor):
        from playwright.sync_api import sync_playwright
        account = self.accounts[actor]
        command = [self.python, str(HERE / "auth.py"), "login",
                   "--issuer", self.issuer, "--client-id", self.client_id,
                   "--profile", str(self.profile(actor))]
        process = subprocess.Popen(command, cwd=ROOT, env=self.actor_environment(actor),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        self.processes.append(process)
        lines = queue.Queue()
        def read_lines():
            for line in process.stdout:
                lines.put(line)
        threading.Thread(target=read_lines, daemon=True).start()
        output = []
        deadline = time.monotonic() + 120
        challenge = None
        try:
            while time.monotonic() < deadline:
                try:
                    line = lines.get(timeout=0.25)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                output.append(line)
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict) and "verification_uri" in item:
                    challenge = item
                    break
            if challenge is None:
                raise RuntimeError("Device authorization did not emit its browser challenge")
            # Trust the public test CA in an isolated browser profile; never bypass TLS checks.
            browser_home = self.actor_directory(actor) / "browser-home"
            browser_env = clean_environment(browser_home, self.ca)
            # Chromium versions use either NSS location; trust only our public CA.
            for relative in (".pki/nssdb", ".local/share/pki/nssdb"):
                database = private_directory(browser_home / relative)
                self.command(["certutil", "-N", "-d", "sql:" + str(database),
                              "--empty-password"], env=browser_env)
                self.command(["certutil", "-A", "-d", "sql:" + str(database),
                              "-n", "HF2L qualification CA", "-t", "C,,", "-i", self.ca], env=browser_env)
            with sync_playwright() as playwright:
                launch = {"headless": True, "env": browser_env}
                if self.args.browser_executable:
                    launch["executable_path"] = self.args.browser_executable
                browser = playwright.chromium.launch(**launch)
                try:
                    page = browser.new_page()
                    page.goto(challenge.get("verification_uri_complete") or challenge["verification_uri"],
                              wait_until="domcontentloaded", timeout=60000)
                    for _ in range(40):
                        if process.poll() is not None:
                            break
                        user_code = page.locator('input[name="user_code"]')
                        if user_code.count() and user_code.is_visible():
                            user_code.fill(challenge["user_code"])
                            page.locator('input[type="submit"], button[type="submit"]').first.click()
                        username = page.locator('input[name="username"]')
                        if username.count() and username.is_visible():
                            username.fill(account["username"])
                        password = page.locator('input[name="password"]')
                        if password.count() and password.is_visible():
                            password.fill(account["password"])
                            page.locator('input[type="submit"], button[type="submit"]').first.click()
                        else:
                            for selector in ['#kc-login', '#kc-accept', 'button[name="accept"]',
                                             'input[name="accept"]', 'button[type="submit"]']:
                                button = page.locator(selector)
                                if button.count() and button.first.is_visible():
                                    button.first.click()
                                    break
                        time.sleep(0.5)
                finally:
                    browser.close()
            process.wait(timeout=40)
            while not lines.empty():
                output.append(lines.get_nowait())
            authentication_log = self.evidence / ("device-login-" + actor + ".log")
            authentication_log.write_text(redact("".join(output), self.secrets))
            authentication_log.chmod(0o600)
            if process.returncode:
                raise RuntimeError("Device authorization failed for " + actor + "; inspect " + str(authentication_log))
            credentials = json.loads((self.profile(actor) / "credentials.json").read_text())
            self.secrets.extend([credentials["access_token"], credentials["refresh_token"]])
            actual = last_json(self.command([self.python, HERE / "auth.py", "identity",
                                             "--profile", self.profile(actor)], actor=actor))
            expected = json.loads(self.identities.read_text())["accounts"][actor]
            if actual["subject"] != expected["subject"]:
                raise AssertionError("Login subject differs from the administrator-verified identity")
            self.record("device-login-" + actor, principal_id=actual["principal_id"])
        finally:
            stop_process(process)

    def client(self, actor):
        from hf2l_exchange.client import ExchangeClient
        return ExchangeClient(self.endpoint, lambda: (self.profile(actor) / "access.token").read_text().strip())

    def refresh(self, actor):
        self.authenticated(actor, [self.python, "-c", "pass"])

    def renewal(self):
        self.refresh("alice")
        profile = self.profile("alice")
        credentials = json.loads((profile / "credentials.json").read_text())
        old_token = credentials["access_token"]
        expires = credentials["expires_at"]
        if float(expires) - time.time() > 110:
            raise RuntimeError("Qualification needs short-lived tokens: initialize with --access-token-seconds 30")
        script = """
import hashlib,json,os,time,httpx
from pathlib import Path
p=Path(os.environ['EXCHANGE_TOKEN_FILE'])
old=hashlib.sha256(p.read_bytes()).hexdigest()
end=time.monotonic()+100
changed=False
while time.monotonic()<end:
 token=p.read_text().strip()
 r=httpx.get(os.environ['EXCHANGE_ENDPOINT']+'/v2/spaces/'+os.environ['VERIFY_SPACE'],headers={'Authorization':'Bearer '+token})
 r.raise_for_status()
 changed |= hashlib.sha256(p.read_bytes()).hexdigest()!=old
 if changed and time.time()>float(os.environ['VERIFY_OLD_EXP'])+1:
  print(json.dumps({'renewed_during_requests':True}));break
 time.sleep(0.5)
else: raise SystemExit('No actual renewal was observed')
"""
        env = self.actor_environment("alice")
        env.update(VERIFY_SPACE=self.space_id, VERIFY_OLD_EXP=str(expires))
        output = self.authenticated("alice", [self.python, "-c", script], env=env, timeout=120)
        if not last_json(output)["renewed_during_requests"]:
            raise AssertionError("No renewal during active requests")
        import httpx
        with httpx.Client(verify=str(self.ca), trust_env=False) as http:
            response = http.get(self.endpoint + "/v2/spaces/" + self.space_id,
                                headers={"Authorization": "Bearer " + old_token})
        if response.status_code != 401:
            raise AssertionError("Actually expired token was not rejected")
        self.record("renewal-during-live-requests-and-expired-token-denial")

    def create_project(self):
        self.project_state = self.evidence / "project-state.json"
        arguments = [self.python, HERE / "project.py", "create", "--state", self.project_state,
                     "--name", "first-federation-" + self.run_id, "--identities", self.identities,
                     "--owner", "owner"]
        command = [self.python, HERE / "auth.py", "run", "--profile",
                   self.profile("bootstrap-admin"), "--", *arguments]
        # Interrupt after durable setup intent, then recover with the same state/key.
        process = subprocess.Popen([str(item) for item in command], cwd=ROOT,
                                   env=self.actor_environment("bootstrap-admin"),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        self.processes.append(process)
        deadline = time.monotonic() + 30
        while process.poll() is None and not self.project_state.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        interrupted = process.poll() is None and self.project_state.exists()
        if interrupted:
            stop_process(process)
        elif process.wait(timeout=10):
            raise RuntimeError("Initial project setup failed before persisting recovery state")
        self.authenticated("bootstrap-admin", arguments)
        state = json.loads(self.project_state.read_text())
        self.space_id = state["space_id"]
        self.authenticated("bootstrap-admin", arguments)
        if json.loads(self.project_state.read_text())["space_id"] != self.space_id:
            raise AssertionError("Setup recovery created a duplicate project")
        self.record("interrupted-setup-recovery", interrupted_after_durable_intent=interrupted,
                    space_id=self.space_id)

    def basic_permissions(self):
        import httpx
        with httpx.Client(verify=str(self.ca), trust_env=False) as http:
            response = http.get(self.endpoint + "/v2/spaces/" + self.space_id)
        if response.status_code != 401:
            raise AssertionError("Anonymous project access was not denied")
        self.refresh("bob")
        with self.client("bob") as client:
            expect_denied(lambda: client.get_space(self.space_id), statuses=(403, 404))
        self.record("anonymous-and-authenticated-nonmember-denial")

    def model(self, actor, action, *args):
        return last_json(self.command([self.python, HERE / "model.py", action, *args], actor=actor))

    def submission_id(self, output):
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        identifier = values.get("resolved_revision") or values.get("submission_revision")
        if not identifier:
            raise AssertionError("Upload did not emit an immutable submission revision")
        return identifier

    def round_args(self, base, output, state):
        return ["round", "--repo-id", self.space_id, "--claim-submissions",
                "--claim-lease-seconds", "300", "--expected-base-revision", base,
                "--run-state", str(state), "--minimum-participants", "2",
                "--output-dir", str(output), "--array-backend", "numpy",
                "--accumulator-dtype", "float64", "--plugin", str(HERE / "model.py"),
                "--plugin-arg", "dataset=" + str(self.actor_directory("owner") / "evaluation.npz"),
                "--publish", "--json"]

    def one_round(self, number, base):
        trained, submissions = {}, {}
        for actor, count in [("alice", 64), ("bob", 96)]:
            workspace = self.actor_directory(actor) / ("round-" + str(number))
            self.app(actor, "download", "--repo-id", self.space_id,
                     "--base-revision", base, "--work-dir", workspace)
            if number == 1 and actor == "alice":
                incompatible = self.actor_directory(actor) / "incompatible"
                shutil.copytree(workspace / "base_model", incompatible)
                config = json.loads((incompatible / "config.json").read_text())
                config["incompatible_example"] = True
                save_json(incompatible / "config.json", config)
                self.app(actor, "upload", "--work-dir", workspace, "--trained-dir", incompatible,
                         "--participant", actor, "--num-examples", str(count), fail=True,
                         expected_error="Model configuration changed")
                self.record("incompatible-checkpoint-rejected")
            destination = workspace / "trained_model"
            training = self.model(actor, "train", "--input", workspace / "base_model",
                                  "--output", destination, "--dataset", self.actor_directory(actor) / "data.npz")
            if training["num_examples"] != count:
                raise AssertionError("Trainer reported the wrong number of local examples")
            trained[actor] = destination
            if number == 1 and actor == "alice":
                impersonation = self.actor_directory(actor) / "impersonation"
                shutil.copytree(workspace, impersonation)
                self.app(actor, "upload", "--work-dir", impersonation, "--trained-dir", destination,
                         "--participant", "bob", "--num-examples", str(count), fail=True,
                         expected_error="Participant must match the authenticated membership")
                self.record("participant-impersonation-rejected")
            submissions[actor] = self.submission_id(self.app(actor, "upload", "--work-dir", workspace,
                "--trained-dir", destination, "--participant", actor, "--num-examples", str(count)))
            if actor == "alice":
                self.refresh("bob")
                with self.client("bob") as client:
                    expect_denied(lambda: client.get_record(self.space_id, submissions["alice"]), statuses=(403, 404))
                if number == 1:
                    result = last_json(self.app("owner", "round", "--repo-id", self.space_id,
                        "--discover-submissions", "--minimum-participants", "2", "--check-only",
                        "--output-dir", self.actor_directory("owner") / "insufficient", "--json"))
                    if result["status"] != "not_ready":
                        raise AssertionError("One participant unexpectedly met a two-participant threshold")
                    self.record("insufficient-submissions-do-not-aggregate")
        self.record("round-" + str(number) + "-peer-private-update-denial")
        output = self.actor_directory("owner") / ("round-" + str(number))
        state = self.actor_directory("owner") / ("round-" + str(number) + "-claim.json")
        if number == 1:
            command = [self.python, HERE / "auth.py", "run", "--profile", self.profile("owner"),
                       "--", self.hf2l, *self.round_args(base, output, state), "--backend", "exchange"]
            with (self.evidence / "interrupted-round.log").open("w") as log:
                process = subprocess.Popen([str(item) for item in command], cwd=ROOT,
                                           env=self.actor_environment("owner"),
                                           stdout=log, stderr=log, start_new_session=True)
                self.processes.append(process)
                deadline = time.monotonic() + 60
                while process.poll() is None and not state.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if process.poll() is not None or not state.exists():
                    raise AssertionError("Could not interrupt a round after its durable fenced claim")
                stop_process(process)
            output = self.actor_directory("owner") / "round-1-resumed"
        result = last_json(self.app("owner", *self.round_args(base, output, state), timeout=300))
        if result["status"] != "published":
            raise AssertionError("Owner did not publish the completed round")
        if not isinstance(result.get("evaluation"), dict) or not result["evaluation"]:
            raise AssertionError("Owner did not evaluate before publication")
        aggregate = Path(result["aggregate_dir"])
        differences = weighted_checkpoint(aggregate, trained["alice"], trained["bob"])
        eligible = {entry["participant"]: entry for entry in result["eligible"]}
        if set(eligible) != {"alice", "bob"}:
            raise AssertionError("Round used unexpected participant identities")
        for actor, count, weight in [("alice", 64, 0.4), ("bob", 96, 0.6)]:
            if eligible[actor]["num_examples"] != count or not math.isclose(eligible[actor]["coefficient"], weight):
                raise AssertionError("Round used incorrect sample weights")
        evaluation = self.model("owner", "evaluate", "--model", aggregate,
                                "--dataset", self.actor_directory("owner") / "evaluation.npz")
        for value in evaluation.values():
            if isinstance(value, (float, int)) and not isinstance(value, bool) and not math.isfinite(value):
                raise AssertionError("Evaluation contains nonfinite metrics")
        publication = result["publication"]
        published = publication.get("resolved_revision") or publication["revision"]
        self.refresh("owner")
        with self.client("owner") as client:
            record = client.get_record(self.space_id, published)
            if record.metadata.get("base_record_id") != base:
                raise AssertionError("Published round does not name its immutable predecessor")
            globals_now = list(client.records(self.space_id, kind="model.global", state="published"))
            if len(globals_now) != number + 1:
                raise AssertionError("Unexpected duplicate global publications")
            snapshot = self.actor_directory("owner") / ("published-" + str(number))
            private_directory(snapshot)
            for attachment in record.attachments:
                destination = snapshot / attachment.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                client.download_attachment(self.space_id, record.id, attachment, destination)
                actual = hashlib.sha256(destination.read_bytes()).hexdigest()
                if actual != attachment.sha256 or destination.stat().st_size != attachment.size:
                    raise AssertionError("Downloaded checkpoint differs from its declared hash/size")
        if number == 1:
            self.app("owner", *self.round_args(base, self.actor_directory("owner") / "stale",
                                               self.actor_directory("owner") / "stale-claim.json"), fail=True,
                     expected_error="Main changed since readiness check")
            self.record("interrupted-fenced-round-recovery-without-duplicate-publication")
            self.record("stale-base-publication-rejected")
        self.record("round-" + str(number) + "-fedavg-hashes-lineage-evaluation",
                    base_revision=base, published_revision=published,
                    maximum_tensor_errors=differences, evaluation=evaluation)
        return published

    def workflow(self):
        self.load_configuration()
        # Server/ML extras must not be required in the participant environment.
        prohibited = ["torch", "fastapi", "uvicorn", "sqlalchemy", "boto3", "psycopg"]
        script = ("import importlib.util,json; names=" + repr(prohibited) +
                  "; print(json.dumps({'present':[n for n in names if importlib.util.find_spec(n)]}))")
        present = last_json(self.command([self.python, "-c", script]))["present"]
        if present:
            raise AssertionError("Participant environment contains server/ML packages: " + ", ".join(present))
        self.record("participant-installation-without-torch-or-server-extras")
        for actor in ["bootstrap-admin", "owner", "alice", "bob"]:
            self.login(actor)
        self.create_project()
        self.basic_permissions()
        for actor, count, seed in [("alice", 64, 11), ("bob", 96, 22)]:
            self.project("owner", "enroll", "--identities", self.identities,
                         "--user", actor, "--participant", actor)
            self.model(actor, "data", "--output", self.actor_directory(actor) / "data.npz",
                       "--examples", str(count), "--seed", str(seed))
        initial = self.actor_directory("owner") / "initial"
        self.model("owner", "init", "--output", initial)
        self.model("owner", "data", "--output", self.actor_directory("owner") / "evaluation.npz",
                   "--examples", "200", "--seed", "33")
        self.app("owner", "init", "--repo-id", self.space_id, "--model-dir", initial)
        self.refresh("owner")
        with self.client("owner") as client:
            base = client.resolve(self.space_id, "main").record_id
        for actor in ["alice", "bob"]:
            invitation_path = self.actor_directory(actor) / "invitation.json"
            self.project("owner", "invite", "--participant", actor,
                         "--source-revision", self.source_revision, "--output", invitation_path)
            invitation = json.loads(invitation_path.read_text())
            if invitation["base_revision"] != base or invitation["participant"] != actor:
                raise AssertionError("Invitation did not preserve immutable base and participant binding")
            if any(word in json.dumps(invitation).lower() for word in ["access_token", "refresh_token", "password"]):
                raise AssertionError("Invitation contains authentication state")
        self.renewal()
        initial_base = base
        base = self.one_round(1, base)
        base = self.one_round(2, base)
        save_json(self.runtime / "last-verification.json", {
            "space_id": self.space_id, "base_revision": base, "initial_revision": initial_base,
            "owner_profile": str(self.profile("owner")), "evidence": str(self.evidence),
        })
        self.record("two-manual-rounds-completed")
        self.revoked_session()

    def revoked_session(self):
        """Invalidate an actual Keycloak session and prove no child is started."""
        import httpx
        profile = self.profile("bob")
        credentials = json.loads((profile / "credentials.json").read_text())
        endpoint = self.issuer + "/protocol/openid-connect/logout"
        with httpx.Client(verify=str(self.ca), trust_env=False) as http:
            response = http.post(endpoint, data={"client_id": self.client_id,
                                 "refresh_token": credentials["refresh_token"]})
            response.raise_for_status()
        sentinel = self.actor_directory("bob") / "must-not-run"
        code = "from pathlib import Path; Path(" + repr(str(sentinel)) + ").touch()"
        self.authenticated("bob", [self.python, "-c", code], fail=True, expected_error="invalid_grant")
        if sentinel.exists():
            raise AssertionError("A child started after session revocation")
        self.record("revoked-session-prevents-command-start")

    def restart(self):
        self.load_configuration()
        previous = json.loads((self.runtime / "last-verification.json").read_text())
        self.stack("stop")
        self.stack("start")
        self.stack("status")
        owner_profile = Path(previous["owner_profile"])
        environment = clean_environment(self.actor_directory("owner"), self.ca, self.endpoint)
        self.command([self.python, HERE / "auth.py", "run", "--profile", owner_profile,
                      "--", self.python, HERE / "project.py", "inspect",
                      "--state", Path(previous["evidence"]) / "project-state.json"], env=environment)
        from hf2l_exchange.client import ExchangeClient
        with ExchangeClient(self.endpoint, lambda: (owner_profile / "access.token").read_text().strip()) as client:
            current = client.resolve(previous["space_id"], "main")
            if current.record_id != previous["base_revision"]:
                raise AssertionError("Persistent restart changed the published reference")
            record = client.get_record(previous["space_id"], current.record_id)
            destination_root = private_directory(self.evidence / "restart-download")
            for attachment in record.attachments:
                destination = destination_root / attachment.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                client.download_attachment(previous["space_id"], record.id, attachment, destination)
                if hashlib.sha256(destination.read_bytes()).hexdigest() != attachment.sha256:
                    raise AssertionError("Restarted checkpoint failed SHA-256 verification")
        self.record("persistent-stop-start-reference-and-checkpoint-download")

    def run(self):
        os.environ.update(NO_PROXY="*", no_proxy="*")
        error = None
        try:
            if self.args.stage in ("bootstrap", "all"):
                self.bootstrap()
            if self.args.stage in ("workflow", "all"):
                self.workflow()
            if self.args.stage in ("restart", "all"):
                self.restart()
        except BaseException as caught:
            error = caught
            self.persist(str(caught))
            raise
        finally:
            for process in reversed(self.processes):
                stop_process(process)
            # Stop only the stack recorded in this private runtime; retain data/evidence.
            if self.config_path.exists():
                try:
                    self.stack("stop")
                    script = (
                        "import importlib.util; from pathlib import Path; "
                        "s=importlib.util.spec_from_file_location('example_stack', " + repr(str(HERE / "stack.py")) + "); "
                        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                        "m.Stack(Path(" + repr(str(self.runtime)) + ")).compose('down', '--remove-orphans')"
                    )
                    self.command([self.python, "-c", script], timeout=120)
                except Exception as cleanup_error:
                    self.persist("Stack cleanup failed: " + str(cleanup_error))
                    if error is None:
                        raise
            if error is None:
                self.persist()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True,
                        help="Private, isolated runtime directory outside the checkout")
    parser.add_argument("--python", default=sys.executable,
                        help="Client-only environment Python; add Playwright as a qualification tool")
    parser.add_argument("--stage", choices=("all", "bootstrap", "workflow", "restart"), default="all",
                        help="Every stage stops owned services afterward; start existing stack before workflow")
    parser.add_argument("--exchange-host", default="exchange.first-federation.test")
    parser.add_argument("--auth-host", default="auth.first-federation.test")
    parser.add_argument("--objects-host", default="objects.first-federation.test")
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--project-name")
    parser.add_argument("--browser-executable")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    verification = Verification(args)
    try:
        verification.run()
    except Exception as error:
        print(json.dumps({"status": "failed", "error": redact(error, verification.secrets),
                          "evidence": str(verification.evidence)}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "passed", "evidence": str(verification.evidence)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
