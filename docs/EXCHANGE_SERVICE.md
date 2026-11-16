# Exchange service overview

The Exchange service transfers model files and associated information between
authorized organizations. Go is the server implementation. Python provides the
client library and training/aggregation application; there is no Python Exchange
server in the current source tree. A space is Exchange's named boundary for
membership, records, and file attachments.

| Component maintained by HF²L | Implementation | Responsibility |
| --- | --- | --- |
| Public Exchange server | Go | Authenticate callers, check space permissions, and coordinate files and metadata. |
| Managed Exchange server | Go | Apply execution-specific identity and grant checks through the trusted managed edge. |
| Private transfer server | Go | Authorize internal storage operations for the trusted gateway. |
| Verification and cleanup worker | Go | Verify completed uploads, recover interrupted work, and remove owned stored data. |
| Client library | Python | Upload/download files and invoke authorized Exchange operations. |
| Training and aggregation application | Python | Run participant training and Org P's model averaging outside the Exchange server. |

A worker is a background program. The managed edge checks the caller before
forwarding a request; the gateway controls file transfers. Exchange does not
install or run training code on participant machines and does not calculate
Federated Averaging, the combination of participant model values.

Choose the guide matching your starting point:

- [First federation](../examples/first_federation/README.md): deploy a complete
  teaching stack and finish two training rounds with separately owned clients.
- [Go services with Docker Compose](../deploy/compose/go/README.md): start Go
  Exchange and its worker, plus an optional Go dashboard, using already prepared
  database, identity, storage, and certificates. Docker Compose starts a group
  of packaged services from a configuration file.
- [Go Exchange](GO_EXCHANGE.md): build/install native executables, configure
  encrypted listeners, check retained data, and operate the worker.
- [Exchange operations](EXCHANGE_V3.md): identity, permissions, storage,
  transfer/recovery contracts, maintenance, and deployment acceptance.
- [Python client package](../packages/exchange/README.md): install the client
  without a server or machine-learning dependencies.

The current request interface remains `/v2`. The older `/v1` Python service,
its command, and its server code have been removed. There is no automatic v1
database importer. The [historical service design](history/EXCHANGE_SERVICE_DESIGN.md)
records the older design; use current guides for executable commands.
