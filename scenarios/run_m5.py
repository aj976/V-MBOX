"""VM-only M5 scenario runner; live event coverage is unverified until VM capture."""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from vmbox.canonical import canonical_json
from vmbox.schema import GroundTruthLabel

_PYTHON_IMAGE = r".*[\\/]python(?:w)?\.exe$"
_WINDOW_NS = [0, 8_000_000_000]  # Script duration plus 3-second collection tolerance.
_FAMILIES = ("child_chain", "query_connect", "benign_lookalike")


def _step(step_id: str, description: str, event_type: str, relation: str,
          earlier: str, relevance: str) -> dict[str, object]:
    return {"step_id": step_id, "description": description, "relevance": relevance,
            "match": {"event_type": event_type, "image_regex": _PYTHON_IMAGE,
                      "ts_window_ns": _WINDOW_NS.copy(),
                      "pid_lineage": {"step_id": earlier, "relation": relation}}}


def build_labels(family: str, seed: int, nonce: str, run_id: str,
                 noise_interval_s: float) -> GroundTruthLabel:
    """Define identity and intended-timing windows before collection or strategy runs."""
    if family not in _FAMILIES or seed < 0:
        raise ValueError("unknown family or negative seed")
    steps = [_step("s1", "scenario Python child", "PROC_START", "child_of", "anchor",
                   "benign" if family == "benign_lookalike" else "attack")]
    if family == "child_chain":
        steps.append(_step("s2", "second Python child", "PROC_START", "child_of", "s1",
                           "attack"))
    elif family == "query_connect":
        steps.extend([
            _step("s2", "query-only handle to child", "MEM_PROCESS_ACCESS", "same_pid",
                  "s1", "attack"),
            _step("s3", "loopback connection", "NET_CONNECT", "same_pid", "s1", "attack"),
        ])
    else:
        steps.append(_step("s2", "benign loopback connection", "NET_CONNECT", "same_pid",
                           "s1", "benign"))
    return GroundTruthLabel.from_dict({
        "scenario_id": family, "run_id": run_id, "seed": seed,
        "anchor": {"nonce": nonce, "event_type": "PROC_START",
                   "image_regex": rf".*vmbox_anchor_{nonce}\.exe$"},
        "steps": steps,
        "benign_workload": f"benign_noise_v1_interval_s={noise_interval_s:.3f}",
        "review_resolutions": [],
    })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=_FAMILIES, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("run only in the isolated Windows VM")
    if args.seed < 0:
        parser.error("seed must be nonnegative")
    if args.out.exists():
        parser.error("output directory must not already exist")
    base = Path(__file__).resolve().parent
    nonce = uuid4().hex
    run_id = str(uuid4())
    rng = random.Random(args.seed)
    noise_interval = round(0.3 + rng.random() * 0.2, 3)
    labels = build_labels(args.family, args.seed, nonce, run_id, noise_interval)
    args.out.mkdir(parents=True)
    with (args.out / "labels.draft.json").open("xb") as stream:
        stream.write(canonical_json(labels.to_dict()))
    if args.family == "child_chain":
        script_args = [str(base / "child_chain.py")]
    elif args.family == "query_connect":
        script_args = [str(base / "injection_like_simulation.py"), "--duration", "5"]
    else:
        script_args = [str(base / "benign_noise.py"), "--duration", "5", "--interval", "1"]
    noise = None
    try:
        with tempfile.TemporaryDirectory(prefix="vmbox-m5-") as temporary:
            command_processor = Path(os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe"))
            marker = Path(temporary) / f"vmbox_anchor_{nonce}.exe"
            shutil.copy2(command_processor, marker)
            noise = subprocess.Popen([sys.executable, str(base / "benign_noise.py"),
                                      "--duration", "5", "--interval", str(noise_interval)])
            command = subprocess.list2cmdline([sys.executable, *script_args])
            subprocess.run([str(marker), "/d", "/c", command], check=True)
            if noise.wait(timeout=15) != 0:
                raise RuntimeError("benign noise workload failed")
    finally:
        if noise is not None and noise.poll() is None:
            noise.terminate()
            noise.wait(timeout=5)
    print(f"run_id: {run_id}")
    print(f"anchor_nonce: {nonce}")
    print(f"draft_labels: {args.out / 'labels.draft.json'}")
    print("scenario_status: completed; live matching unverified until trace capture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
