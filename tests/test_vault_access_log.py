"""Tests for hermes.vault_access_log.VaultAccessLog — the tamper-evident,
hash-chained record of every original-value retrieval from a TokenVault."""

from hermes.vault_access_log import VaultAccessLog


def _log(tmp_path, name="access_log.db") -> VaultAccessLog:
    return VaultAccessLog(db_path=str(tmp_path / name), signing_key=b"\x01" * 32)


def test_log_access_returns_sequential_chained_records(tmp_path):
    log = _log(tmp_path)
    r1 = log.log_access("tok_a", "txn_1", "ws1", "alice@example.com")
    r2 = log.log_access("tok_b", "txn_2", "ws1", "alice@example.com")

    assert r1.chain_position == 0
    assert r2.chain_position == 1
    assert r2.previous_record_hash == r1.record_hash
    assert log.verify() is True


def test_persists_across_restart(tmp_path):
    db_path = str(tmp_path / "persist.db")
    log1 = VaultAccessLog(db_path=db_path, signing_key=b"\x02" * 32)
    log1.log_access("tok_a", "txn_1", "ws1", "alice@example.com")
    log1.log_access("tok_b", "txn_2", "ws1", "bob@example.com")

    log2 = VaultAccessLog(db_path=db_path, signing_key=b"\x02" * 32)
    assert len(log2.export_log()) == 2
    assert log2.verify() is True


def test_verify_detects_tampered_record(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "tamper.db")
    log = VaultAccessLog(db_path=db_path, signing_key=b"\x03" * 32)
    log.log_access("tok_a", "txn_1", "ws1", "alice@example.com")

    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE vault_access_log SET accessed_by = ? WHERE chain_position = 0",
        ("mallory@example.com",),
    )
    conn.commit()
    conn.close()

    tampered = VaultAccessLog(db_path=db_path, signing_key=b"\x03" * 32)
    assert tampered.verify() is False


def test_verify_detects_broken_chain_linkage(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "break_link.db")
    log = VaultAccessLog(db_path=db_path, signing_key=b"\x04" * 32)
    log.log_access("tok_a", "txn_1", "ws1", "alice@example.com")
    log.log_access("tok_b", "txn_2", "ws1", "alice@example.com")

    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE vault_access_log SET previous_record_hash = ? WHERE chain_position = 1",
        ("0" * 64,),
    )
    conn.commit()
    conn.close()

    reopened = VaultAccessLog(db_path=db_path, signing_key=b"\x04" * 32)
    assert reopened.verify() is False


def test_export_log_filters_by_workspace(tmp_path):
    log = _log(tmp_path)
    log.log_access("tok_a", "txn_1", "ws1", "alice@example.com")
    log.log_access("tok_b", "txn_2", "ws2", "bob@example.com")
    log.log_access("tok_c", "txn_3", "ws1", "alice@example.com")

    assert len(log.export_log()) == 3
    ws1_records = log.export_log(workspace_id="ws1")
    assert len(ws1_records) == 2
    assert all(r.workspace_id == "ws1" for r in ws1_records)


def test_different_signing_key_fails_verification(tmp_path):
    db_path = str(tmp_path / "wrong_key.db")
    log = VaultAccessLog(db_path=db_path, signing_key=b"\x05" * 32)
    log.log_access("tok_a", "txn_1", "ws1", "alice@example.com")

    reopened_wrong_key = VaultAccessLog(db_path=db_path, signing_key=b"\x06" * 32)
    assert reopened_wrong_key.verify() is False
