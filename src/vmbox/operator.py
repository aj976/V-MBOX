"""Local operator profiles and derived output paths (not evidence)."""

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from vmbox.canonical import canonical_json


@dataclass(frozen=True)
class Profile:
    name: str
    role: str
    lab_root: Path
    trial: str
    endpoint: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", self.name) is None:
            raise ValueError("invalid profile name")
        if self.role not in {"anchor", "monitored"}:
            raise ValueError("profile role must be anchor or monitored")
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", self.trial) is None:
            raise ValueError("invalid trial identifier")
        if not self.lab_root.is_absolute():
            raise ValueError("lab root must be absolute")
        from vmbox.anchor.transport import _endpoint

        _endpoint(self.endpoint)

    @property
    def key_dir(self) -> Path:
        prefix = "anchor_keys" if self.role == "anchor" else "anchor_public"
        return self.lab_root / f"{prefix}_{self.trial}"

    @property
    def public_key(self) -> Path:
        return self.key_dir / "public.pem"

    @property
    def auth_key(self) -> Path:
        return self.key_dir / "auth.key"


def profile_directory() -> Path:
    override = os.environ.get("VMBOX_PROFILE_DIR")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "V-MBOX" / "profiles" if base else Path.home() / ".vmbox" / "profiles"


def save_profile(profile: Profile) -> Path:
    from vmbox.anchor.ledger import write_once

    path = profile_directory() / f"{profile.name}.json"
    write_once(path, canonical_json({"name": profile.name, "role": profile.role,
                                     "lab_root": str(profile.lab_root),
                                     "trial": profile.trial, "endpoint": profile.endpoint}))
    return path


def load_profile(name: str, role: str | None = None) -> Profile:
    if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) is None:
        raise ValueError("invalid profile name")
    path = profile_directory() / f"{name}.json"
    data = json.loads(path.read_bytes())
    if type(data) is not dict or set(data) != {"name", "role", "lab_root", "trial", "endpoint"}:
        raise ValueError("invalid operator profile")
    profile = Profile(data["name"], data["role"], Path(data["lab_root"]),
                      data["trial"], data["endpoint"])
    if canonical_json(data) != path.read_bytes() or profile.name != name:
        raise ValueError("noncanonical or mismatched operator profile")
    if role is not None and profile.role != role:
        raise ValueError(f"profile {name} is for {profile.role}, expected {role}")
    return profile


def default_export(evidence: Path) -> Path:
    return evidence.resolve().with_name(f"anchor_export_{evidence.name}")


def default_report(evidence: Path) -> Path:
    return evidence.resolve().with_name(f"report_{evidence.name}")


def _session_pointer(profile: Profile) -> Path:
    return profile_directory() / f"{profile.name}.last_session.json"


def _valid_session(profile: Profile, evidence: Path) -> bool:
    from vmbox.store.manifest import read_manifest

    root = profile.lab_root.resolve()
    if evidence.parent != root or not evidence.name.startswith("live_"):
        return False
    try:
        manifest = read_manifest(evidence / "manifest.json")
    except (OSError, ValueError):
        return False
    if manifest.mode != "live" or manifest.anchor is None \
            or manifest.anchor.endpoint != profile.endpoint:
        return False
    if profile.public_key.exists():
        from vmbox.anchor.receipt_crypto import load_public_key, public_key_fingerprint

        try:
            fingerprint = public_key_fingerprint(load_public_key(profile.public_key))
        except (OSError, ValueError):
            return False
        if manifest.anchor.pubkey_fingerprint != fingerprint:
            return False
    return True


def remember_session(profile: Profile, evidence: Path) -> None:
    """Atomically update a local convenience pointer; evidence is untouched."""
    evidence = evidence.resolve()
    if not _valid_session(profile, evidence):
        raise ValueError("recorded session does not match the monitored profile")
    path = _session_pointer(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".last_session_", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json({"evidence": str(evidence)}))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def latest_session(profile: Profile) -> Path:
    """Resolve the current session or find the newest matching live manifest.

    The fallback supports sessions recorded before the pointer was introduced.
    """
    pointer = _session_pointer(profile)
    if pointer.exists():
        raw = pointer.read_bytes()
        data = json.loads(raw)
        if type(data) is not dict or set(data) != {"evidence"} \
                or type(data["evidence"]) is not str or raw != canonical_json(data):
            raise ValueError("invalid last-session pointer; use --evidence explicitly")
        evidence = Path(data["evidence"]).resolve()
        if not _valid_session(profile, evidence):
            raise ValueError("last session is missing or mismatched; use --evidence explicitly")
        return evidence
    candidates = [path.resolve() for path in profile.lab_root.glob("live_*")
                  if path.is_dir() and _valid_session(profile, path.resolve())]
    if not candidates:
        raise ValueError("no matching live session found; record first or use --evidence")
    candidates.sort(key=lambda path: (path / "manifest.json").stat().st_mtime_ns,
                    reverse=True)
    if len(candidates) > 1 and (candidates[0] / "manifest.json").stat().st_mtime_ns == \
            (candidates[1] / "manifest.json").stat().st_mtime_ns:
        raise ValueError("multiple equally recent sessions; use --evidence explicitly")
    return candidates[0]
