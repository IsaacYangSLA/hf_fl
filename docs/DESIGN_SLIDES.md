---
marp: true
theme: default
paginate: true
size: 16:9
title: Hugging Face Federated Averaging Design
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

## Training fan-out — every client starts from the same immutable commit

| Participant A | Hugging Face model repository | Participant B |
|:---|:---:|---:|
| Private dataset A | **`main @ C_r`** | Private dataset B |
| ↓ exact-SHA download | model + config + round manifest | exact-SHA download ↓ |
| download → own trainer → upload<br>or trusted local plugin | versioned coordination plane | download → own trainer → upload<br>or trusted local plugin |
| local checkpoint → | **PR A** &nbsp;&nbsp; **PR B** | ← local checkpoint |

## Aggregation fan-in — only the owner publishes the global model

| Inputs | Repository owner | Output |
|:---|:---|:---|
| Pinned PR A commit<br>Pinned PR B commit | Validate author allowlist, ancestry, round, schema, shapes and counts<br>**FedAvg + optional owner evaluation** | Commit `C_(r+1)` to `main`<br>Record manifest + optional tag |

> The Hub stores and transports checkpoints. It is not a privacy boundary:
> raw data stays local, but uploaded weights are visible to authorized readers.

<!-- _footer: "Trust boundaries: each participant, the repository owner, and the Hugging Face Hub." -->

---

# 2. Operation sequence

| Step | Actor | Operation | Required guard |
|---:|:---|:---|:---|
| 1 | Owner | Run `python -m hf2l.init_repo`; publish round 0 | Record returned commit `C0` |
| 2 | Owner | Send repository ID and `C0` to A and B | Send the SHA—not “latest” |
| 3 | A + B | Run `python -m hf2l.client_download`, then any local trainer | Write a separate compatible checkpoint |
| 4 | A + B | Run `python -m hf2l.client_upload` to validate and open PRs | `parent_commit=C0`; private data stays local |
| 5 | Owner | Discover open PRs or use explicit refs; pin SHAs | Allowlisted authors; current base + round |
| 6 | Owner | Dry-run validation, weighted FedAvg, optional evaluation | Reject stale, incompatible or non-finite updates |
| 7 | Owner | Publish aggregate and optional round tag | Commit to `main` with parent `C0` |

**Round transition**

`main @ C0` → parallel client PRs → owner aggregation → `main @ C1` → repeat

> If `main` changed after validation, Hugging Face rejects publication. The
> owner restarts from the new base instead of overwriting concurrent work.

<!-- _footer: "Client PRs are closed after aggregation; neither local checkpoint is merged directly." -->

---

# 3. Credential management

| Actor | Capability | Credential policy |
|:---|:---|:---|
| Owner: initialization | Create repository and first commit | Narrowly scoped owner write token |
| Participant | Read `C_r`; authenticate and upload a PR | Each participant's own token; never the owner's token |
| Owner: aggregation | Read PR refs; update only `main` | Separate repository-scoped write token |
| Automated publisher | Publish one repository from CI | Prefer a short-lived trusted-publisher token |

**Resolution used by the scripts**

`--token` → `HF_TOKEN` → active `hf auth login` cache

- Interactive workstation: use `hf auth login`, then verify with
  `hf auth whoami`.
- Automation: inject `HF_TOKEN` from a secret manager; mask logs and rotate it.
- Avoid `--token` for routine use because arguments may appear in history and
  process listings. Never commit tokens, `.env` files, or credential caches.
- Public repo: enable PRs. Private repo: grant explicit organization access.

<!-- _footer: "Sources: [HF authentication](https://huggingface.co/docs/huggingface_hub/en/quick-start) · [Access tokens](https://huggingface.co/docs/hub/security-tokens) · [HF pull requests](https://huggingface.co/docs/hub/repositories-pull-requests-discussions)" -->

---

# 4. Handling large models

> The workflow supports one SafeTensors file or an indexed, deterministically
> sharded checkpoint. Aggregation processes one shard at a time.

| Stage | Scalable design |
|:---|:---|
| **Package** | Deterministic sharded SafeTensors + index. All clients use the same architecture, names, dtypes and shard layout. |
| **Transfer** | Use `huggingface_hub >= 0.32`, exact revisions and a fast local Xet cache. Hub APIs handle large-file transfer. |
| **Aggregate** | Process one shard/tensor from every accepted client, accumulate in FP32/FP64 on CPU, write the output shard, then release input memory. |
| **Finalize** | Validate config, index, tensor schemas and non-finite values. Publish the model plus a round manifest with `parent_commit=C_r`. |

**Resource profile:** memory is bounded by one output shard plus active tensors
and the FP32/FP64 accumulator; disk holds every selected snapshot and one output.

Xet uses content-defined chunks around 64 KiB, deduplicates known chunks, and
adapts transfer concurrency. Dense training may alter bytes throughout every
weight file, so deduplication can be limited. Deltas or adapters reduce traffic
only when the protocol defines how they are reconstructed and aggregated.

<!-- _footer: "HF docs: [Xet](https://huggingface.co/docs/hub/xet/deduplication) · [uploads](https://huggingface.co/docs/huggingface_hub/guides/upload) · [checkpoint sharding](https://huggingface.co/docs/transformers/models)" -->
