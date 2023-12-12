import json

import chatmaild
from chatmaild.newemail import create_newemail_dict, print_new_account


def test_create_newemail_dict(example_config):
    ac1 = create_newemail_dict(example_config)
    assert "@" in ac1["email"]
    assert len(ac1["password"]) >= 10

    ac2 = create_newemail_dict(example_config)

    assert ac1["email"] != ac2["email"]
    assert ac1["password"] != ac2["password"]


def test_print_new_account(capsys, monkeypatch, maildomain, tmpdir, example_config):
    monkeypatch.setattr(chatmaild.newemail, "CONFIG_PATH", str(example_config._inipath))
    print_new_account()
    out, err = capsys.readouterr()
    lines = out.split("\n")
    assert lines[0] == "Content-Type: application/json"
    assert not lines[1]
    dic = json.loads(lines[2])
    assert dic["email"].endswith(f"@{example_config.mail_domain}")
    assert len(dic["password"]) >= 10
