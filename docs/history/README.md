# History

These frozen reviews, findings, remediation notes, designs and slides describe
their original baselines. A proposed rewrite in this directory is not a claim
that the rewrite was completed. The current architecture and its known
[implementation limitations](../ARCHITECTURE_V3.md#current-implementation-limitations)
are documented in [architecture v3](../ARCHITECTURE_V3.md), and the current independent Exchange
runbook is [EXCHANGE_V3.md](../EXCHANGE_V3.md). Historical test counts apply only
to the code and environment identified by the original document.
The source distribution retains these documents so links from the v3 comparison
remain reviewable; their inclusion does not make them current specifications.

| Document | Historical scope |
|---|---|
| `ARCHITECTURE_REVIEW.md` | Principal-engineer review of the pre-cutover package and a broad proposed rewrite; selected concepts are incorporated into v3 |
| `ARCHITECTURE_REVIEW_AND_V2_DESIGN.md` | Design of the independent Exchange implementation developed in the sibling `hf_fl-v2` checkout |
| `EXCHANGE_V2.md` | Sibling v2 operational contract and local verification record before integration into this checkout |
| `EXCHANGE_REVIEW_FINDINGS.md` | Verified findings against the exchange service at `9f670c9` |
| `EXCHANGE_REMEDIATION.md` | Status of each finding after remediation |
| `EXCHANGE_SERVICE_DESIGN.md` | Original design of the legacy exchange service |
| `DESIGN_SLIDES.md` | Four-slide overview of the original two-backend design |
