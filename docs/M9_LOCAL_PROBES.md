# M9 local trust-boundary probes

`tests/test_m9_resilience.py` uses synthetic, throwaway files. These are unit
tests of the current verifier, not observations from the Windows lab.

| Synthetic change | Local chain check | Receipt check |
|---|---|---|
| Change an event before sealing, omit another event, or alter a timestamp before sealing | Accepts the internally consistent bytes | No independent source truth to compare |
| Replace every segment in a copied two-segment chain, recomputing both hashes while retaining original host receipts | Accepts the rewritten local chain | Rejects because the signed checkpoint hash differs |
| Remove host receipts while retaining the anchor export | Local chain remains readable | Reports incomplete host receipt tail against export |

The first row is the compromised-collector limit: integrity checks cannot tell
whether the collector reported every source event or preserved its timestamps.
The second row applies only when the separate anchor's key and receipt state
remain available. Existing byte-flip tests cover segment header/body/footer,
tombstone, and receipt corruption separately.

VM process-kill, power-off, and anchor transport behavior are **unverified until
run on Windows VM**. M9's final behavior table and DESIGN.md threat-model review
must use those runs; no VM outcome is inferred from these unit tests.
