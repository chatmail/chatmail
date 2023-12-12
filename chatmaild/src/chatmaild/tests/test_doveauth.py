import json
import pytest
import threading
import queue
import traceback

import chatmaild.doveauth
from chatmaild.doveauth import get_user_data, lookup_passdb, handle_dovecot_request
from chatmaild.database import DBError


def test_basic(db, make_config):
    config = make_config("c1.testrun.org")
    lookup_passdb(db, config, "link2xt@c1.testrun.org", "Pieg9aeToe3eghuthe5u")
    data = get_user_data(db, "link2xt@c1.testrun.org")
    assert data
    data2 = lookup_passdb(db, config, "link2xt@c1.testrun.org", "Pieg9aeToe3eghuthe5u")
    assert data == data2


def test_dont_overwrite_password_on_wrong_login(db, make_config):
    """Test that logging in with a different password doesn't create a new user"""
    config = make_config("something.org")
    res = lookup_passdb(db, config, "newuser1@something.org", "kajdlkajsldk12l3kj1983")
    assert res["password"]
    res2 = lookup_passdb(db, config, "newuser1@something.org", "kajdlqweqwe")
    # this function always returns a password hash, which is actually compared by dovecot.
    assert res["password"] == res2["password"]


def test_nocreate_file(db, monkeypatch, tmpdir, make_config):
    config = make_config("something.org")
    p = tmpdir.join("nocreate")
    p.write("")
    monkeypatch.setattr(chatmaild.doveauth, "NOCREATE_FILE", str(p))
    lookup_passdb(db, config, "newuser1@something.org", "zequ0Aimuchoodaechik")
    assert not get_user_data(db, "newuser1@something.org")


def test_db_version(db):
    assert db.get_schema_version() == 1


def test_too_high_db_version(db):
    with db.write_transaction() as conn:
        conn.execute("PRAGMA user_version=%s;" % (999,))
    with pytest.raises(DBError):
        db.ensure_tables()


def test_handle_dovecot_request(db, make_config):
    config = make_config("c3.testrun.org")
    msg = (
        "Lshared/passdb/laksjdlaksjdlaksjdlk12j3l1k2j3123/"
        "some42@c3.testrun.org\tsome42@c3.testrun.org"
    )
    res = handle_dovecot_request(msg, db, config)
    assert res
    assert res[0] == "O" and res.endswith("\n")
    userdata = json.loads(res[1:].strip())
    assert userdata["home"] == "/home/vmail/some42@c3.testrun.org"
    assert userdata["uid"] == userdata["gid"] == "vmail"
    assert userdata["password"].startswith("{SHA512-CRYPT}")


def test_50_concurrent_lookups_different_accounts(
    db, gencreds, make_config, maildomain
):
    num_threads = 50
    req_per_thread = 5
    results = queue.Queue()
    config = make_config(maildomain)

    def lookup(db):
        for i in range(req_per_thread):
            addr, password = gencreds()
            try:
                lookup_passdb(db, config, addr, password)
            except Exception:
                results.put(traceback.format_exc())
            else:
                results.put(None)

    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=lookup, args=(db,), daemon=True)
        threads.append(thread)

    print(f"created {num_threads} threads, starting them and waiting for results")
    for thread in threads:
        thread.start()

    for i in range(num_threads * req_per_thread):
        res = results.get()
        if res is not None:
            pytest.fail(f"concurrent lookup failed\n{res}")
