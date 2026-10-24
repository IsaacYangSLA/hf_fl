# Call sequence diagrams

Open [call-sequences.html](call-sequences.html) in a browser. The page contains
four rendered SVG diagrams and their Mermaid source, with navigation, zoom,
SVG download, and print support. It works offline without a CDN or web server.

These diagrams describe the public Exchange `/v2` SDK transfer paths and the
HF²L Exchange adapter. They were originally traced against implementation commit
`e090800`; later source annotations and rendering limits are recorded below.
They show normal paths and selected recovery paths, including multipart retries,
worker category changes, and acquisition recovery. The [architecture limitations](../ARCHITECTURE_V3.md#current-implementation-limitations)
and [Exchange runbook](../EXCHANGE_V3.md) remain the detailed operational references.
The FedAvg validation annotations were synchronized on October 8, 2026 to
reflect verification of supplied schema-1 hashes and finite-input filtering.
This update preserves the existing SVG layout; it does not claim a new Mermaid
render or live-provider validation. The round diagram describes synchronous
FedAvg; [manual cyclic handoffs](../TRAINING_GUIDE.md#cyclic-federated-learning-without-fedavg)
use a separate caller-controlled sequence.
Authentication tokens come from an external identity provider; space membership,
types, policy, and the private versioned bucket are prerequisites. Public access
tokens are validated against the configured issuer, audience and `exchange` scope;
FedAvg participant identity comes from the authenticated member's server binding.

| Sequence | Editable Mermaid | Rendered SVG | Main source paths |
|---|---|---|---|
| Upload and publish | [exchange-upload.mmd](exchange-upload.mmd) | [SVG](exchange-upload.svg) | [SDK](../../packages/exchange/src/hf2l_exchange/client.py), [transfers](../../packages/exchange/src/hf2l_exchange/transfers.py), [worker](../../packages/exchange/src/hf2l_exchange/worker.py) |
| Read and download | [exchange-download.mmd](exchange-download.mmd) | [SVG](exchange-download.svg) | [transfer client](../../packages/exchange/src/hf2l_exchange/transfer_client.py), [authorization](../../packages/exchange/src/hf2l_exchange/auth.py), [storage](../../packages/exchange/src/hf2l_exchange/storage.py) |
| Worker and cleanup | [exchange-worker.mmd](exchange-worker.mmd) | [SVG](exchange-worker.svg) | [worker](../../packages/exchange/src/hf2l_exchange/worker.py), [transfers](../../packages/exchange/src/hf2l_exchange/transfers.py), [cancellation](../../packages/exchange/src/hf2l_exchange/application.py) |
| Federated round | [fedavg-round.mmd](fedavg-round.mmd) | [SVG](fedavg-round.svg) | [client steps](../../hf2l/client_steps.py), [runner](../../hf2l/fedavg_runner.py), [adapter](../../hf2l/backends/exchange.py), [application transactions](../../packages/exchange/src/hf2l_exchange/application.py), [FedAvg profile](../../packages/exchange/src/hf2l_exchange/profiles.py) |

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

## Regenerate

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
