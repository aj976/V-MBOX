"""M3 genesis is independent of the pending journal/segment format decision."""

from hashlib import sha256

from hypothesis import given
from hypothesis import strategies as st

from vmbox.integrity.genesis import manifest_genesis
from vmbox.schema import AnchorInfo, SessionManifest


@given(st.integers(min_value=0, max_value=2**63 - 1), st.text(max_size=20))
def test_manifest_genesis_matches_canonical_bytes_and_is_stable(start_ts_ns, host):
    manifest = SessionManifest(
        schema_version=1,
        mode="live",
        session_id="00000000-0000-4000-8000-000000000001",
        boot_id="boot",
        host=host,
        start_ts_ns=start_ts_ns,
        collector_version="0.1.0",
        config_hash="sha256:" + "0" * 64,
        strategy="context_aware",
        budget_bytes=1024,
        journal_bytes=128,
        anchor=AnchorInfo("host:port", "sha256:" + "1" * 64),
    )
    expected = sha256(manifest.to_json()).digest()
    assert manifest_genesis(manifest) == expected
    assert manifest_genesis(manifest) == manifest_genesis(manifest)


def test_manifest_change_changes_genesis():
    base = SessionManifest(
        1, "live", "00000000-0000-4000-8000-000000000001", "boot", "host", 0, "0.1.0",
        "sha256:" + "0" * 64, "fixed", 1024, 128,
        AnchorInfo("host:port", "sha256:" + "1" * 64),
    )
    changed = SessionManifest.from_dict({**base.to_dict(), "start_ts_ns": 1})
    assert manifest_genesis(base) != manifest_genesis(changed)
