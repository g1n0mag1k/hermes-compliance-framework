"""
tests/test_cli_operator.py — operator commands used by the Docker deployment:
hermes-relay keystore-init / keystore-public-key / export-receipts and
hermes-verify chain.
"""

from __future__ import annotations

import pytest

import gateway.evidence as gateway_evidence
from gateway.policy import HIPAA_PRODUCTION_BLOCK, EnforcementDecision
from hermes.cli import main as relay_main
from hermes.receipts.v2.cli import main as verify_main
from hermes.receipts.v2.key_store import KeyStore
from hermes.workspaces import create_workspace

PASSPHRASE = "operator-cli-test-passphrase"


@pytest.fixture()
def keystore_env(tmp_path, monkeypatch):
    import hermes.workspaces as ws_mod

    keystore_path = tmp_path / "keys" / "gateway.keystore"
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(keystore_path))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE)
    monkeypatch.setattr(ws_mod, "_DEFAULT_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        ws_mod, "_DEFAULT_REGISTRY_DB", str(tmp_path / "workspaces" / "registry.db")
    )
    ws_mod._chain_cache.clear()
    yield keystore_path
    monkeypatch.undo()
    ws_mod._chain_cache.clear()
    gateway_evidence.reset_v2_chains()


def _decision(decision: str) -> EnforcementDecision:
    policy = HIPAA_PRODUCTION_BLOCK
    return EnforcementDecision(
        decision=decision,  # type: ignore[arg-type]
        reasons=["test"],
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_digest=policy.digest,
        content_types_inspected=["application/json"],
        content_types_not_inspected=[],
        all_detectors_clean=True,
    )


def _init_keystore(capsys) -> str:
    relay_main(["keystore-init"])
    out = capsys.readouterr().out
    return next(line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("key_id: "))


def test_keystore_init_creates_keystore_and_refuses_overwrite(keystore_env, capsys):
    key_id = _init_keystore(capsys)
    original = keystore_env.read_bytes()

    store = KeyStore.open(keystore_env, PASSPHRASE.encode())
    assert store.key_id == key_id
    assert oct(keystore_env.stat().st_mode & 0o777) == "0o600"

    with pytest.raises(SystemExit) as exc:
        relay_main(["keystore-init"])
    assert exc.value.code == 1
    assert "refusing to overwrite" in capsys.readouterr().err
    assert keystore_env.read_bytes() == original


def test_keystore_commands_require_env(monkeypatch, capsys):
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)
    for command in ("keystore-init", "keystore-public-key"):
        with pytest.raises(SystemExit) as exc:
            relay_main([command])
        assert exc.value.code == 2
    assert "must both be set" in capsys.readouterr().err


def test_keystore_public_key_missing_keystore(keystore_env, capsys):
    with pytest.raises(SystemExit) as exc:
        relay_main(["keystore-public-key"])
    assert exc.value.code == 1
    assert "keystore-init" in capsys.readouterr().err


def test_keystore_public_key_matches_keystore(keystore_env, capsys):
    key_id = _init_keystore(capsys)
    relay_main(["keystore-public-key"])
    captured = capsys.readouterr()
    signer = KeyStore.open(keystore_env, PASSPHRASE.encode()).load_signer()
    assert captured.out == signer.public_key_manifest()["public_key_pem"]
    assert f"key_id: {key_id}" in captured.err


def test_export_receipts_and_verify_chain(keystore_env, tmp_path, capsys):
    key_id = _init_keystore(capsys)
    gateway_evidence.reset_v2_chains()
    workspace, _ = create_workspace("cli-export-ws", "CLI Export", "ops@test.example")
    for decision, forwarded in (("ALLOW", True), ("BLOCK", False), ("ALLOW", True)):
        gateway_evidence.issue_gateway_receipt(
            workspace,
            f"gw_{decision.lower()}",
            _decision(decision),
            "openai",
            "/v1/chat/completions",
            {"HIPAA_SSN": 1} if decision == "BLOCK" else {},
            {},
            {},
            forwarded=forwarded,
        )

    out_dir = tmp_path / "export"
    relay_main(["export-receipts", "--workspace", workspace.workspace_id, "--out", str(out_dir)])
    stdout = capsys.readouterr().out
    files = sorted(p.name for p in out_dir.glob("*.cose"))
    assert len(files) == 3
    assert files[0].startswith("00000000-ALLOW-")
    assert files[1].startswith("00000001-BLOCK-")
    assert "decision=BLOCK forwarded=False" in stdout
    pem = out_dir / "gateway-public.pem"
    assert pem.exists()

    block_file = out_dir / files[1]
    assert verify_main(["receipt", str(block_file), "--public-key", str(pem)]) == 0

    assert verify_main(
        ["chain", str(out_dir), "--public-key", str(pem), "--workspace-id", workspace.workspace_id]
    ) == 0
    chain_out = capsys.readouterr().out
    assert chain_out.splitlines()[0] == "VALID"
    assert "receipts: 3" in chain_out
    assert f"signer_key_ids: {key_id}" in chain_out

    assert verify_main(
        ["chain", str(out_dir), "--public-key", str(pem), "--workspace-id", "other-ws"]
    ) == 1

    (out_dir / files[1]).unlink()
    assert verify_main(["chain", str(out_dir), "--public-key", str(pem)]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_verify_chain_rejects_tampered_receipt(keystore_env, tmp_path, capsys):
    _init_keystore(capsys)
    gateway_evidence.reset_v2_chains()
    workspace, _ = create_workspace("cli-tamper-ws", "CLI Tamper", "ops@test.example")
    gateway_evidence.issue_gateway_receipt(
        workspace, "gw_one", _decision("BLOCK"), "openai", "/v1/chat/completions", {}, {}, {}
    )
    out_dir = tmp_path / "export"
    relay_main(["export-receipts", "--workspace", workspace.workspace_id, "--out", str(out_dir)])
    receipt = next(out_dir.glob("*.cose"))
    data = bytearray(receipt.read_bytes())
    data[-1] ^= 0x01
    receipt.write_bytes(bytes(data))
    assert verify_main(["chain", str(out_dir), "--public-key", str(out_dir / "gateway-public.pem")]) == 1


def test_export_receipts_refuses_nonempty_dir_and_unknown_workspace(keystore_env, tmp_path, capsys):
    _init_keystore(capsys)
    workspace, _ = create_workspace("cli-nonempty-ws", "CLI", "ops@test.example")
    out_dir = tmp_path / "export"
    out_dir.mkdir()
    (out_dir / "old.cose").write_bytes(b"x")
    with pytest.raises(SystemExit) as exc:
        relay_main(["export-receipts", "--workspace", workspace.workspace_id, "--out", str(out_dir)])
    assert exc.value.code == 1

    with pytest.raises(SystemExit) as exc:
        relay_main(["export-receipts", "--workspace", "no-such-ws", "--out", str(tmp_path / "x")])
    assert exc.value.code == 1


def test_verify_chain_malformed_input(tmp_path):
    pem = tmp_path / "k.pem"
    pem.write_text("x")
    assert verify_main(["chain", str(tmp_path / "missing"), "--public-key", str(pem)]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert verify_main(["chain", str(empty), "--public-key", str(pem)]) == 2
