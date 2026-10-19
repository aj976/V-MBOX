# TECHSTACK — V-MBOX

Versions are intentionally unpinned here. Pin them in `pyproject.toml` / lockfiles at M0 and record them in every experiment's metadata.

## 1. Decisions

| Area | Choice | Why | Alternative / escape hatch |
|---|---|---|---|
| Platform | Windows 10/11 (lab VM) | Project target | None planned |
| Core language | Python 3.11+ | Fast iteration for pipeline, analysis, eval in one language | Move only the measured-hot collector path to C# or C++ if drops/overhead demand it |
| ETW consumption | `pywintrace` (ETW via Python) to start | Quickest way to get Kernel-Process / Kernel-Network events | .NET `TraceEvent` or native ETW (C#/C++) behind the same `Source` interface |
| Sysmon | Sysinternals Sysmon, read via Windows Event Log subscription (`pywin32` / `EvtSubscribe`) | Provides remote-thread, process-access, image-load events | Parse exported `.evtx` for replay and tests |
| Serialization | Canonical JSON (stdlib `json`, sorted keys, compact) | Debuggable, reproducible hashes | `orjson` for speed if profiling shows need (keep canonical output identical) |
| Hashing / signatures | `hashlib` (SHA-256), `cryptography` (Ed25519) | Standard, audited | None |
| Storage | Custom journal + segment files | Control over chain, torn writes, tombstones | SQLite only for *analysis indexes*, never as evidence store |
| Anchor transport | TLS over TCP (or named pipe for local testing) with a pre-shared credential | Simple, testable | mTLS if time permits |
| CLI | `typer` (or `argparse` if avoiding dependencies) | Clean subcommands | |
| Analysis | `pandas`, `numpy`, `scipy` (CIs, Kendall tau), `matplotlib` | Standard eval stack | |
| Report | Static HTML via `jinja2` + embedded JS-free CSS (JSON alongside) | Single-file shareable output | Markdown export |
| Testing | `pytest`, `hypothesis` (property tests for chain/segments), `pytest-cov` | Chain and parser logic benefit from property tests | |
| Quality | `ruff`, `mypy` (strict on `integrity/` and `store/`) | Catch bugs in critical modules | |
| Packaging | `pyproject.toml`, `uv` or `pip` + venv | | |
| VM / lab | Hyper-V or VirtualBox, Windows VM with snapshot; second VM (or the host) for the anchor | Clean resets, safe attack simulation, forced power-off tests | |
| Attack simulation | Custom scripted scenarios + Atomic Red Team tests, only inside the isolated VM | Known, labeled sequences | |
| Version control | Git; experiment outputs tagged with commit hash | Reproducibility | |

## 2. Environment setup (target)

Host machine:
1. Install Hyper-V (or VirtualBox).
2. Create a Windows VM, install Python, Sysmon, VS Build Tools only if a native collector is needed.
3. Install Sysmon with a minimal config enabling event IDs 1, 3, 5, 7, 8, 10 (config committed to `docs/sysmon.xml`; reviewed so noise volume is known).
4. Take a clean snapshot before every experiment batch.
5. Create the anchor VM (or run anchor on the host) with its own Ed25519 key, never copied into the monitored VM.

Dev loop:
```
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

## 3. Dependencies to validate in M1 (do not assume)

- Does `pywintrace` deliver Kernel-Process and Kernel-Network events at the volumes the VM generates, without loss? Measure drop counters.
- Is Sysmon event latency acceptable for the journal flush policy?
- Is any memory-protection-change source usable without protected-process signing? If not, `MEM_PROTECT_CHANGE` stays out of v1.
- Is Python's overhead acceptable at the target event rate? If not, port only the collector.

## 4. Things deliberately not used

- Kernel drivers (signing, risk, scope).
- Threat-Intelligence ETW provider (requires protected consumer).
- Any real malware. Scenarios are scripted simulations of behavior patterns.
- Cloud services. Everything runs locally in the lab.
