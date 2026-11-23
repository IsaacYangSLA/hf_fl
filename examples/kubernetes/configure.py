#!/usr/bin/env python3
"""Render namespace-local Kubernetes JSON manifests without third-party packages."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


def manifests(
    role: str, image: str, space: str, endpoint: str, *, recovery_config: dict | None = None,
) -> dict[str, dict]:
    if role not in {"alice", "bob", "owner"}:
        raise ValueError("role must be alice, bob, or owner")
    if not image.strip() or any(c.isspace() for c in image):
        raise ValueError("image must be a container image reference")
    if not space.strip():
        raise ValueError("space must be the existing Exchange space identifier")
    url = urlsplit(endpoint)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("endpoint must be an HTTPS Exchange URL without credentials, query, or fragment")
    name = "hf2l-" + role
    labels = {"app.kubernetes.io/name": "hf2l-study", "app.kubernetes.io/instance": name}
    def claim(suffix):
        return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": name + "-" + suffix, "labels": labels},
                "spec": {"accessModes": ["ReadWriteOnce"],
                         "resources": {"requests": {"storage": "1Gi"}}}}
    pod = {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                            "runAsGroup": 10001, "fsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "hf2l", "image": image, "imagePullPolicy": "IfNotPresent",
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "1", "memory": "512Mi"}},
                        "volumeMounts": [{"name": "data", "mountPath": "/data", "readOnly": True},
                                         {"name": "state", "mountPath": "/work"},
                                         {"name": "temporary", "mountPath": "/tmp"},
                                         {"name": "credentials", "mountPath": "/credentials", "readOnly": True}],
                        "env": [{"name": "EXCHANGE_ENDPOINT", "value": endpoint},
                                {"name": "EXCHANGE_TOKEN_FILE", "value": "/credentials/token"},
                                {"name": "SSL_CERT_FILE", "value": "/credentials/ca.crt"},
                                {"name": "HF2L_SPACE_ID", "value": space}]}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": name + "-data"}},
                    {"name": "state", "persistentVolumeClaim": {"claimName": name + "-state"}},
                    {"name": "temporary", "emptyDir": {"sizeLimit": "256Mi"}},
                    {"name": "credentials", "secret": {"secretName": name + "-exchange", "defaultMode": 288}}],
    }
    arguments = ["listen", "--backend", "exchange", "--repo-id", space,
                 "--state-dir", "/work/listener"]
    if role == "owner":
        arguments += ["--role", "owner", "--minimum-participants", "2", "--array-backend", "numpy",
                      "--plugin", "/opt/hf2l/examples/first_federation/model.py"]
    else:
        arguments += ["--participant", role, "--plugin", "/opt/hf2l/examples/kubernetes/trainer.py"]
    arguments += ["--plugin-arg", "dataset=/data/private-data.npz"]
    pod["containers"][0].update(command=["hf2l"], args=arguments)
    deployment = {"apiVersion": "apps/v1", "kind": "Deployment",
                  "metadata": {"name": name, "labels": labels},
                  "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                           "selector": {"matchLabels": labels},
                           "template": {"metadata": {"labels": labels}, "spec": pod}}}
    data_pod = copy.deepcopy(pod)
    data_pod["restartPolicy"] = "Never"
    data_pod["volumes"] = [v for v in data_pod["volumes"] if v["name"] in {"data", "temporary"}]
    data_container = data_pod["containers"][0]
    data_container.pop("env")
    data_container["volumeMounts"] = [{"name": "data", "mountPath": "/data"}, {"name": "temporary", "mountPath": "/tmp"}]
    data_container["command"] = ["python", "/opt/hf2l/examples/first_federation/model.py"]
    examples, seed = {"alice": (64, 11), "bob": (96, 22), "owner": (80, 33)}[role]
    data_container["args"] = ["data", "--output", "/data/private-data.npz", "--examples", str(examples), "--seed", str(seed)]
    data_job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name + "-data"},
                "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": labels}, "spec": data_pod}}}
    result = {"storage.json": {"apiVersion": "v1", "kind": "List", "items": [claim("data"), claim("state")]},
              "data-job.json": data_job, "listener.json": deployment}
    if role == "owner":
        init_pod = copy.deepcopy(pod)
        init_pod["restartPolicy"] = "Never"
        init_pod["containers"][0]["command"] = ["python", "/opt/hf2l/examples/kubernetes/initialize.py"]
        init_pod["containers"][0].pop("args")
        result["owner-init.json"] = {"apiVersion": "batch/v1", "kind": "Job",
                                    "metadata": {"name": name + "-init"},
                                    "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": labels}, "spec": init_pod}}}

    if recovery_config is not None:
        if role == "owner" or not isinstance(recovery_config, dict):
            raise ValueError("Recovery settings require an Alice or Bob role and a JSON object")
        config_name = name + "-recovery-config"
        result["recovery-config.json"] = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": config_name, "labels": labels},
            "immutable": True,
            "data": {"config.json": json.dumps(recovery_config, sort_keys=True)},
        }
        container = pod["containers"][0]
        container["args"][container["args"].index("--state-dir") + 1] = "/work/recovery-listener"
        container["args"] += [
            "--recovery-root", "/work/recovery",
            "--recovery-config", "/recovery-config/config.json",
        ]
        container["volumeMounts"].append({
            "name": "recovery-config", "mountPath": "/recovery-config", "readOnly": True,
        })
        pod["volumes"].append({
            "name": "recovery-config", "configMap": {"name": config_name},
        })
    return result


def main() -> None:
    if sys.version_info < (3, 14, 0, "final", 0) or sys.version_info >= (3, 16):
        raise SystemExit(
            "Rendering HF²L Kubernetes resources requires Python 3.14 or 3.15. "
            f"Running Python {sys.version.split()[0]}. "
            "Run this command with python3.14 or python3.15."
        )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["alice", "bob", "owner"], required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--space", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--recovery-config", type=Path, help="Participant recovery settings in JSON")
    args = parser.parse_args()
    try:
        recovery = json.loads(args.recovery_config.read_text(encoding="utf-8")) if args.recovery_config else None
        if args.recovery_config is not None and not isinstance(recovery, dict):
            raise ValueError("Recovery settings must be a JSON object")
        output = manifests(args.role, args.image, args.space, args.endpoint, recovery_config=recovery)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, manifest in output.items():
        (args.output_dir / name).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Rendered " + ", ".join(output))


if __name__ == "__main__":
    main()
