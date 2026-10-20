"""M7 CLI preserves incomplete status and displays unknown bounds explicitly."""

from pathlib import Path

from test_recovery import _unbounded

from vmbox.cli import main


def test_recover_and_timeline_show_surviving_events(tmp_path: Path, capsys) -> None:
    directory = _unbounded(tmp_path)
    assert main(["recover", "--evidence", str(directory)]) == 0
    output = capsys.readouterr().out
    assert "recovery: ok" in output
    assert "recovered_events: 3" in output
    assert "offline evaluation session, not forensic evidence" in output
    assert main(["timeline", "--evidence", str(directory)]) == 0
    output = capsys.readouterr().out
    assert "seq=0" in output and "seq=1" in output and "seq=2" in output
    assert "integrity=chained" in output


def test_torn_journal_is_incomplete_and_renders_unknown(tmp_path: Path, capsys) -> None:
    directory = _unbounded(tmp_path)
    journal = directory / "journal.bin"
    with journal.open("r+b") as stream:
        stream.seek(72)
        original = stream.read(1)
        stream.seek(72)
        stream.write(bytes([original[0] ^ 1]))
    assert main(["recover", "--evidence", str(directory)]) == 3
    output = capsys.readouterr().out
    assert "recovery: incomplete" in output
    assert "seq=unknown ts_ns=unknown" in output
    assert "seq=0..0" not in output
