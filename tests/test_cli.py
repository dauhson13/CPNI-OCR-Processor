import pytest

from piiscan import cli


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    monkeypatch.setattr(cli, "ENV_FILE", env)
    monkeypatch.setattr(cli.safety, "install_excepthook", lambda: None)
    monkeypatch.setattr(cli.os, "umask", lambda mask: 0)
    monkeypatch.setattr(cli.safety, "load_key", lambda path: b"k" * 32)
    for name in ("PIISCAN_ROOT", "PIISCAN_OTHER"):
        monkeypatch.delenv(name, raising=False)
    calls = []
    import piiscan.scan

    monkeypatch.setattr(piiscan.scan, "run", lambda root, *a: calls.append(root) or {})
    return env, calls


def test_load_env_is_literal_and_env_wins(isolated, monkeypatch):
    env, _ = isolated
    env.write_text('# comment\n\nPIISCAN_ROOT=\\\\fileserver\\Customer Docs\nPIISCAN_OTHER="quoted"\n')
    monkeypatch.setenv("PIISCAN_OTHER", "from-env")
    cli.load_env(env)
    assert cli.os.environ["PIISCAN_ROOT"] == "\\\\fileserver\\Customer Docs"
    assert cli.os.environ["PIISCAN_OTHER"] == "from-env"


def test_scan_uses_env_root_unless_given(isolated, tmp_path):
    env, calls = isolated
    share, other = tmp_path / "share", tmp_path / "other"
    share.mkdir()
    other.mkdir()
    env.write_text(f"PIISCAN_ROOT={share}\n")
    cli.main(["scan", "--db", str(tmp_path / "x.db")])
    cli.main(["scan", str(other), "--db", str(tmp_path / "x.db")])
    assert calls == [share, other]


def test_scan_without_root_explains(isolated, tmp_path, capsys):
    env, _ = isolated
    env.write_text("PIISCAN_ROOT=\n")
    with pytest.raises(SystemExit):
        cli.main(["scan"])
    assert "PIISCAN_ROOT" in capsys.readouterr().err
