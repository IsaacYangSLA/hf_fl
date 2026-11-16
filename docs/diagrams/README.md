# Historical call sequence diagrams

These retained diagrams describe the earlier Python-service implementation,
originally traced at `e090800`, with later federated-round annotations. They
preserve protocol and recovery design context; Python credential helpers,
thread pools and method names are historical implementation details. They do
not qualify the current native Go services. Use the
[current architecture](../ARCHITECTURE_V3.md), [Go Exchange guide](../GO_EXCHANGE.md)
and [Exchange runbook](../EXCHANGE_V3.md) for current implementation and operations.

Open [call-sequences.html](call-sequences.html) in a browser. The page contains
four rendered SVG images and their editable Mermaid sequence descriptions,
with navigation, zoom, image download and print support. It works offline.
Source links below use the fixed pre-removal repository baseline. The image
geometry is retained; this documentation update does not claim a new rendering
or live-provider validation. The round diagram describes synchronous FedAvg;
[manual cyclic handoffs](../TRAINING_GUIDE.md#cyclic-federated-learning-without-fedavg)
follow a separate caller-controlled sequence.

| Sequence | Editable Mermaid | Rendered SVG | Main source paths |
|---|---|---|---|
| Upload and publish | [exchange-upload.mmd](exchange-upload.mmd) | [SVG](exchange-upload.svg) | [SDK](https://github.com/IsaacYangSLA/hf_fl/blob/e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb/packages/exchange/src/hf2l_exchange/client.py), [transfers](../../packages/exchange/internal/transfers/transfers.go), [worker](../../packages/exchange/internal/worker/worker.go) |
| Read and download | [exchange-download.mmd](exchange-download.mmd) | [SVG](exchange-download.svg) | [transfer client](https://github.com/IsaacYangSLA/hf_fl/blob/e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb/packages/exchange/src/hf2l_exchange/transfer_client.py), [authorization](../../packages/exchange/internal/auth/auth.go), [storage](../../packages/exchange/internal/storage/s3.go) |
| Worker and cleanup | [exchange-worker.mmd](exchange-worker.mmd) | [SVG](exchange-worker.svg) | [worker](../../packages/exchange/internal/worker/worker.go), [transfers](../../packages/exchange/internal/transfers/transfers.go), [cancellation](../../packages/exchange/internal/service/records.go) |
| Federated round | [fedavg-round.mmd](fedavg-round.mmd) | [SVG](fedavg-round.svg) | [client steps](https://github.com/IsaacYangSLA/hf_fl/blob/e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb/hf2l/client_steps.py), [runner](https://github.com/IsaacYangSLA/hf_fl/blob/e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb/hf2l/fedavg_runner.py), [adapter](https://github.com/IsaacYangSLA/hf_fl/blob/e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb/hf2l/backends/exchange.py), [application transactions](../../packages/exchange/internal/service/records.go), [FedAvg profile](../../packages/exchange/internal/profiles/profiles.go) |

The API lane groups HTTP routing, authentication, application commands, and
transfer orchestration. The database represents the configured metadata store;
deployment uses PostgreSQL. Blob storage is the shipped versioned S3 adapter;
S3-compatible services require the same multipart and exact-version semantics.
Presigning happens locally in the service and is not a separate storage request. Large client transfers go directly to storage;
the worker separately reads stored bytes for verification. Upload completion,
attachment verification, record publication, and reference advancement are
distinct operations.

The federated-round view combines each caller's local adapter/SDK into one lane
and refers to the generic transfer diagrams for file operations. It assumes a
published initial global model and depicts owner-triggered aggregation after
client submissions. It does not depict an automatic Exchange webhook trigger,
HF/JFrog transport behavior, or cyclic handoffs. The worker view isolates the
cancellation race and cleanup dispatch; it does not depict every repair state.
The complete retry, cleanup, revocation, and failure state machines remain in
the implementation and runbook.

These are scoped call sequences, not a complete system topology. They do not
show the optional `hf2l-jobs` control plane, qualified CPU sandbox, managed
workload certificate authentication, or the managed execution proxy and download
broker. Those paths have separate ingress and authorization contracts in the
[Exchange runbook](../EXCHANGE_V3.md) and
[job manager deployment guide](../../deploy/jobs/README.md).
The architecture's [backend capability table](../ARCHITECTURE_V3.md#fl-documents-checkpoints-and-publication)
describes why the Exchange sequence cannot be applied unchanged to HF, JFrog
or LocalStore. No diagram step represents a human approval receipt; the public
HF²L CLI has no such built-in gate. Membership and policy checks in the API lane
remain mandatory.

## Regenerate historical renderings

Edit the `.mmd` files, then run the [renderer](../../scripts/render_call_sequences.mjs)
from the repository root. Rendering uses Node.js, a local Chrome/Chromium binary,
and Mermaid; it does not change the application's Python dependencies. The
generated HTML embeds SVGs and source text, not the Mermaid runtime.

The checked rendering used Mermaid 11.12.0 and Puppeteer Core 24.43.1. Install
those tools in a temporary directory if they are not already available:

```bash
npm install --prefix /tmp/hf2l-diagram-tools --no-save \
  mermaid@11.12.0 puppeteer-core@24.43.1

node scripts/render_call_sequences.mjs \
  --mermaid /tmp/hf2l-diagram-tools/node_modules/mermaid/dist/mermaid.min.js \
  --puppeteer /tmp/hf2l-diagram-tools/node_modules/puppeteer-core \
  --browser /usr/bin/google-chrome
```

Use the actual path to an installed Chrome/Chromium binary. In a trusted local
rendering environment that cannot run Chrome's sandbox, the renderer accepts
`--no-sandbox`; use it only when the trusted rendering environment requires it.
No network is used by the rendering page. Regeneration overwrites the four SVGs
and `call-sequences.html`; review them alongside changes to the Mermaid sources.

The renderer uses Mermaid's [documented rendering API](https://mermaid.js.org/config/usage.html).
