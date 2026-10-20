# M5 query-connect development run — observed result

Source: [canonical evaluation result](M5_QUERY_CONNECT_SEED1_UNBOUNDED.result.json), transcribed from the Windows VM operator's output in this chat. The raw trace and frozen labels remain on the VM; this repository has not independently reproduced the run. The trace hash and label hash in the result match the hashes the operator posted at capture and freeze.

The `query_connect` seed-1 unbounded offline replay retained 11,272,443 bytes and reported collection coverage and evidence coverage of 1.0 for its frozen, manually reviewed attack steps. This is coverage of the scripted labels in this run, not proof of complete Sysmon collection. Sysmon upstream loss was not measured. The result recorded storage efficiency of 0.2790635534817076 relevant persisted events per MiB. No latency, event-loss, crash-recovery, or reconstruction metric was measured.

The VM's `verify` output reported a matching local sealed-segment hash chain and a readable, unverified journal. This was an `offline_eval` session with integrity level `chained` at best: **offline evaluation session, not forensic evidence**. The anchor and second-VM behavior were not exercised. This single development run supports the M5 pipeline smoke test only; it does not support a strategy comparison or variance claim.
