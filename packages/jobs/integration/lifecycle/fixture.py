"""Private independent Exchange and tiny ML inputs for the opt-in Go lifecycle test.

This fixture never imports or invokes a Python manager, scheduler, controller,
executor, node agent, gateway, or execution proxy. Manager services run in Go.
Resource credentials and generated private keys remain in the explicit runtime.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time

BASE_FILE = Path(__file__).resolve().parents[1] / "gateway_backend_fixture.py"
_spec = importlib.util.spec_from_file_location("hf2l_lifecycle_exchange_base", BASE_FILE)
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

PLUGIN = """
from pathlib import Path
import json
import hashlib
import time
import numpy as np
from safetensors.numpy import load_file, save_file

def initialize_model(output_dir, options):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "config.json").write_text(json.dumps({"model_type":"hf2l-lifecycle-linear","features":2,"labels":2}, sort_keys=True))
    save_file({"weight":np.zeros((2,2),dtype=np.float32),"bias":np.zeros(2,dtype=np.float32)}, str(output / "model.safetensors"))
    return {"fixture":"synthetic linear-model lifecycle; not a model-quality benchmark"}

def train_model(base_dir, output_dir, options):
    time.sleep(float(options.get("delay_seconds",15)))
    dataset = np.load(options["dataset_npz"],allow_pickle=False)
    values = dataset["values"]
    tensors = load_file(str(Path(base_dir) / "model.safetensors"))
    delta = np.float32(values.mean())
    output = Path(output_dir)
    output.mkdir(parents=True,exist_ok=True)
    (output / "config.json").write_bytes((Path(base_dir) / "config.json").read_bytes())
    save_file({name:(tensor+delta).astype(np.float32) for name,tensor in tensors.items()},str(output / "model.safetensors"))
    return {"num_examples":int(values.shape[0]),"fixture_delta":float(delta)}
"""


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Fixture(_base.Fixture):
    def __init__(self, *args):
        super().__init__(*args)
        self.extra_children = []
        self.extra_logs = []

    def start(self):
        super().start()
        private = self.root
        _base.private_file(private / "client-ca-key.pem", self.ca_key.private_bytes(
            _base.serialization.Encoding.PEM, _base.serialization.PrivateFormat.PKCS8,
            _base.serialization.NoEncryption()))
        _base.private_file(private / "workload-key.pem", self.workload_key.private_bytes(
            _base.serialization.Encoding.PEM, _base.serialization.PrivateFormat.PKCS8,
            _base.serialization.NoEncryption()))
        _base.private_file(private / "workload-public.pem", self.public(self.workload_key).encode())
        _base.private_file(private / "backend-secret", self.secret.encode())
        _base.private_file(private / "admin-token", self.human_token().encode())

        import numpy as np
        for participant, count, value in (("alice",16,1.0),("bob",24,2.0)):
            path = private / (participant + ".npz")
            np.savez(path, values=np.full((count,2),value,dtype=np.float32))
            os.chmod(path,0o444)
        source = private / "source-mirror"
        source.mkdir(mode=0o700)
        (source / "trainer.py").write_text(PLUGIN)
        environment = {**os.environ, "GIT_CONFIG_NOSYSTEM":"1",
                       "GIT_CONFIG_GLOBAL":os.devnull}
        def git(*args):
            result = subprocess.run(["git","-C",str(source),*args],env=environment,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=15,check=True,text=True)
            return result.stdout.strip()
        git("init","--quiet")
        git("add","trainer.py")
        git("-c","user.name=HF2L lifecycle fixture","-c","user.email=fixture@example.invalid",
            "commit","--quiet","-m","Freeze synthetic two-client lifecycle trainer")
        commit = git("rev-parse","HEAD")

        environment = os.environ.copy()
        for name in tuple(environment):
            if name.startswith("EXCHANGE_") or name.lower() in {"http_proxy","https_proxy","all_proxy","no_proxy"}:
                environment.pop(name)
        st = self.settings.storage
        environment.update({
            "PYTHONPATH":str(_base.REPO / "packages/exchange/src"),
            "PYTHONDONTWRITEBYTECODE":"1","AWS_EC2_METADATA_DISABLED":"true",
            "EXCHANGE_DATABASE_URL":self.settings.database.url,
            "EXCHANGE_ISSUER":self.issuer,"EXCHANGE_AUDIENCE":"exchange","EXCHANGE_ADMIN_SUBJECT":"provisioner",
            "EXCHANGE_JWT_PUBLIC_KEY":self.public(self.owner_key),
            "EXCHANGE_WORKLOAD_ISSUER":self.workload_issuer,
            "EXCHANGE_WORKLOAD_AUDIENCE":"exchange-managed",
            "EXCHANGE_WORKLOAD_PUBLIC_KEY":self.public(self.workload_key),
            "EXCHANGE_TRUSTED_BACKEND_SECRET":self.secret,
            "EXCHANGE_PROVISIONING_PRINCIPAL_IDS":_base.principal_id(self.issuer,"provisioner"),
            "EXCHANGE_DOWNLOAD_BROKER_PRINCIPAL_IDS":_base.principal_id(self.issuer,"provisioner"),
            "EXCHANGE_S3_ENDPOINT":st.endpoint,"EXCHANGE_S3_BUCKET":st.bucket,
            "EXCHANGE_S3_ACCESS_KEY":st.access_key,"EXCHANGE_S3_SECRET_KEY":st.secret_key,
            "EXCHANGE_S3_REGION":st.region,"EXCHANGE_S3_PREFIX":st.prefix,
            "EXCHANGE_PART_SIZE":str(st.part_size),
            "EXCHANGE_ALLOW_LOCAL_HTTP":"true" if st.allow_local_http else "false",
        })
        endpoints = {"ordinary": self.public_endpoint, "managed": self.managed_endpoint} if self.native_binary else {}
        modes = () if self.native_binary else (
            ("ordinary","hf2l_exchange.api:create_app"),
            ("managed","hf2l_exchange.api:create_managed_app"),
        )
        for name, factory in modes:
            port = free_port()
            log = os.fdopen(os.open(private/(name+".log"),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb")
            self.extra_logs.append(log)
            command = [sys.executable,"-m","uvicorn",factory,"--factory",
                "--host","127.0.0.1","--port",str(port),"--ssl-certfile",str(self.server_cert),
                "--ssl-keyfile",str(self.server_key),"--no-access-log","--log-level","warning"]
            if name=="managed":
                command.extend(["--ssl-ca-certs",str(self.ca_file),"--ssl-cert-reqs","2"])
            child = subprocess.Popen(command,env=environment,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            self.extra_children.append(child)
            endpoint = "https://127.0.0.1:"+str(port)
            context = ssl.create_default_context(cafile=str(self.ca_file))
            if name=="managed":
                context.load_cert_chain(str(self.backend_cert),str(self.backend_key))
            with _base.httpx.Client(verify=context,trust_env=False,timeout=2) as client:
                deadline=time.monotonic()+30
                while True:
                    if child.poll() is not None:
                        raise RuntimeError("Independent Exchange API stopped: "+name)
                    try:
                        response=client.get(endpoint+"/ready")
                        if response.status_code==200:
                            break
                    except _base.httpx.HTTPError:
                        pass
                    if time.monotonic()>deadline:
                        raise TimeoutError("Independent Exchange readiness: "+name)
                    time.sleep(.05)
            endpoints[name]=endpoint
        ready = {
            "ordinary_endpoint":endpoints["ordinary"],
            "managed_backend_endpoint":endpoints["managed"],
            "gateway_backend_endpoint":self.endpoint,
            "service_ca_file":str(self.ca_file),"client_ca_file":str(self.ca_file),
            "client_ca_key_file":str(private/"client-ca-key.pem"),
            "server_certificate":str(self.server_cert),"server_key":str(self.server_key),
            "backend_client_certificate":str(self.backend_cert),"backend_client_key":str(self.backend_key),
            "backend_secret_file":str(private/"backend-secret"),
            "admin_token_file":str(private/"admin-token"),
            "workload_issuer":self.workload_issuer,
            "workload_public_key_file":str(private/"workload-public.pem"),
            "workload_private_key_file":str(private/"workload-key.pem"),
            "source_mirror":str(source),"source_commit":commit,
            "datasets":{p:str(private/(p+".npz")) for p in ("alice","bob")},
            "dataset_sha256":{p:hashlib.sha256((private/(p+".npz")).read_bytes()).hexdigest() for p in ("alice","bob")},
            "fixture_versions":{"python":sys.version.split()[0],"numpy":np.__version__},
            "exchange_runtime":self.runtime_receipt(),
            "storage":{"endpoint":st.endpoint,"bucket":st.bucket,"prefix":st.prefix.strip("/"),
                       "region":st.region,"registration_id":"lifecycle-object-store",
                       "capacity_bytes":2*1024**3},
            "worker_fixture":"numpy/safetensors only; no Python manager import or process",
        }
        _base.private_json(private/"lifecycle-ready.json",ready)

    def run(self):
        last_worker = 0.0
        while not self.stop:
            if (self.child.poll() is not None or not self.native_children_alive()
                    or any(c.poll() is not None for c in self.extra_children)):
                raise RuntimeError("Independent Exchange process stopped")
            if not self.native_binary and time.monotonic()-last_worker>=.05:
                _base.tick(self.transfers)
                last_worker=time.monotonic()
            for path in sorted((self.root/"commands").glob("*.json")):
                body=_base.resource_json(path);path.unlink()
                try:
                    if set(body)!={"action"}:
                        raise ValueError("Invalid fixture command")
                    response={"ok":True,"result":self.action(body["action"])}
                except Exception as exc:
                    response={"ok":False,"error":type(exc).__name__}
                _base.private_json(self.root/"replies"/path.name,response)
            time.sleep(.02)

    def close(self):
        for child in self.extra_children:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        for log in self.extra_logs:
            log.close()
        super().close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--runtime",required=True)
    parser.add_argument("--database-config",required=True)
    parser.add_argument("--storage-config",required=True)
    args=parser.parse_args()
    fixture=Fixture(Path(args.runtime).resolve(),_base.resource_json(args.database_config),
                    _base.resource_json(args.storage_config))
    signal.signal(signal.SIGTERM,lambda *_:setattr(fixture,"stop",True))
    signal.signal(signal.SIGINT,lambda *_:setattr(fixture,"stop",True))
    try:
        fixture.start()
        fixture.run()
    except Exception as exc:
        _base.private_json(fixture.root/"failure.json",{"error":type(exc).__name__})
        return 1
    finally:
        fixture.close()
    return 0

if __name__=="__main__":
    raise SystemExit(main())
