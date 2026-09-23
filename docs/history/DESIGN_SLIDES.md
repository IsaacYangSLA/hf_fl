---
marp: true
theme: default
paginate: true
size: 16:9
title: HF²L Multi-Backend Federated Learning Design
style: |
  section {
    padding: 34px 46px;
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    font-size: 20px;
    line-height: 1.28;
    color: #172033;
  }
  h1 {
    margin: 0 0 16px;
    color: #173f67;
    font-size: 36px;
    line-height: 1.08;
  }
  h2 {
    margin: 12px 0 7px;
    color: #256b73;
    font-size: 22px;
  }
  table {
    width: 100%;
    font-size: 17px;
    line-height: 1.2;
  }
  th {
    background: #173f67;
    color: white;
  }
  td, th {
    padding: 7px 10px;
  }
  blockquote {
    margin: 12px 0 0;
    padding: 8px 14px;
    border-left: 5px solid #29a3a3;
    background: #eef8f8;
    color: #173f67;
  }
  code {
    font-size: 0.86em;
  }
  footer {
    font-size: 11px;
    color: #687386;
  }
---

# 1. System architecture

## Training fan-out — every client starts from the same immutable revision

| Participant A | Model repository | Participant B |
|:---|:---:|---:|
| Private dataset A | **`main @ C_r`** | Private dataset B |
| ↓ exact-revision download | model + config + round manifest | exact-revision download ↓ |
| download → own trainer → upload<br>or trusted local plugin | versioned coordination plane | download → own trainer → upload<br>or trusted local plugin |
| local checkpoint → | **submission A** &nbsp;&nbsp; **submission B** | ← local checkpoint |

## Aggregation fan-in — only the owner publishes the global model

| Inputs | Repository owner | Output |
|:---|:---|:---|
| Pinned A revision<br>Pinned B revision | Validate uploader allowlist, base, round, hashes and tensor schema<br>**FedAvg + optional owner evaluation** | Publish `C_(r+1)` to `main`<br>Record manifest + optional tag |

> Hugging Face Hub uses PR refs; JFrog HuggingFaceML uses unique named
> revisions discovered with AQL. Neither backend is a privacy boundary:
> raw data stays local, but uploaded weights are visible to authorized readers.

<!-- _footer: "Trust boundaries: each participant, the repository owner, and the configured model store." -->

---

# 2. Operation sequence

| Step | Actor | Operation | Required guard |
|---:|:---|:---|:---|
| 1 | Owner | Run `python -m hf2l.init_repo`; publish round 0 | Record returned revision `C0` |
| 2 | Owner | Send repository ID and `C0` to A and B | Send immutable ID—not “latest” |
| 3 | A + B | Run `python -m hf2l.client_download`, then any local trainer | Write a separate compatible checkpoint |
| 4 | A + B | Run `python -m hf2l.client_upload` | Hub PR or unique JFrog revision; data stays local |
| 5 | Owner | Discover or explicitly select submissions | Allowlisted uploaders; current base + round |
| 6 | Owner | Dry-run validation, weighted FedAvg, optional evaluation | Reject stale, incompatible or non-finite updates |
| 7 | Owner | Publish aggregate and optional round tag/revision | Hub CAS or single JFrog coordinator |

**Round transition**

`main @ C0` → parallel client submissions → owner aggregation → `main @ C1` → repeat

> Hub provides atomic `parent_commit` protection. JFrog is rechecked before
> publication and requires one writer or an external coordinator lock.

<!-- _footer: "Client submissions remain separate; no local checkpoint is published directly to main." -->

---

# 3. Credential management

| Actor | Capability | Credential policy |
|:---|:---|:---|
| Owner: initialization | Create/initialize repository and first revision | Narrowly scoped owner write token |
| Participant | Read `C_r`; upload an isolated submission | Each participant's own token; never the owner's token |
| Owner: aggregation | Read submissions; update only `main` | Separate repository-scoped write token |
| Automated publisher | Publish one repository from CI | Prefer a short-lived trusted-publisher token |

**Resolution used by the scripts**

Hub: `--token` → `HF_TOKEN` → active `hf auth login` cache<br>
JFrog: `--token` → `JFROG_ACCESS_TOKEN` → `HF_TOKEN`

- Interactive workstation: use `hf auth login`, then verify with
  `hf auth whoami`.
- JFrog: set `HF_ENDPOINT=.../api/huggingfaceml/REPO_KEY`; create the local
  repository as an administrator and disable participant overwrite permission.
- Automation: inject tokens from a secret manager; mask logs and rotate them.
- Avoid `--token` for routine use because arguments may appear in history and
  process listings. Never commit tokens, `.env` files, or credential caches.
- Hub: enable PRs. JFrog: scope read/deploy rights by repository and identity.

<!-- _footer: "Backends: Hugging Face Hub and JFrog Artifactory HuggingFaceML." -->

---

# 4. Handling large models

> The workflow supports one SafeTensors file or an indexed, deterministically
> sharded checkpoint. Aggregation processes one shard at a time.

| Stage | Scalable design |
|:---|:---|
| **Package** | Deterministic sharded SafeTensors + index. All clients use the same architecture, names, dtypes and shard layout. |
| **Transfer** | Use exact revisions and a local cache. Hub supports Xet; current JFrog HuggingFaceML versions can enable Xet for files over 50 GB. |
| **Aggregate** | Process one shard/tensor from every accepted client, accumulate in FP32/FP64 on CPU, write the output shard, then release input memory. |
| **Finalize** | Validate hashes, config, index, tensor schemas and non-finite values. Publish the model plus a round manifest naming `base_revision=C_r`. |

**Resource profile:** memory is bounded by one output shard plus active tensors
and the FP32/FP64 accumulator; disk holds every selected snapshot and one output.

Xet uses content-defined chunks around 64 KiB, deduplicates known chunks, and
adapts transfer concurrency. Dense training may alter bytes throughout every
weight file, so deduplication can be limited. Deltas or adapters reduce traffic
only when the protocol defines how they are reconstructed and aggregated.

<!-- _footer: "Use backend-supported huggingface_hub and hf_xet versions; aggregate one deterministic SafeTensors shard at a time." -->
