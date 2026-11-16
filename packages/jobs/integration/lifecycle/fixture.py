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



class Fixture(_base.Fixture):
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

        st = self.settings.storage
        endpoints = {"ordinary": self.public_endpoint, "managed": self.managed_endpoint}
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
        while not self.stop:
            if self.child.poll() is not None or not self.native_children_alive():
                raise RuntimeError("Independent Exchange process stopped")
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
