#!/usr/bin/env python3
import sys
from pathlib import Path


def main(vmail_dir=None):
    if vmail_dir is None:
        vmail_dir = sys.argv[1]

    accounts = 0
    ci_accounts = 0

    for path in Path(vmail_dir).iterdir():
        if not path.is_dir() or not (path / "cur").is_dir():
            continue
        accounts += 1
        if path.name[:3] in ("ci-", "ac_"):
            ci_accounts += 1

    print("# HELP total number of accounts")
    print("# TYPE accounts gauge")
    print(f"accounts {accounts}")
    print("# HELP number of CI accounts")
    print("# TYPE ci_accounts gauge")
    print(f"ci_accounts {ci_accounts}")
    print("# HELP number of non-CI accounts")
    print("# TYPE nonci_accounts gauge")
    print(f"nonci_accounts {accounts - ci_accounts}")


if __name__ == "__main__":
    main()
