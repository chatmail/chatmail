"""
Chat Mail pyinfra deploy.
"""
import importlib.resources
from pathlib import Path

from pyinfra import host, logger
from pyinfra.operations import apt, files, server, systemd, python
from pyinfra.facts.files import File
from .acmetool import deploy_acmetool


def _install_chatmaild() -> None:
    chatmaild_filename = "chatmaild-0.1.tar.gz"
    chatmaild_path = importlib.resources.files(__package__).joinpath(
        f"../../../dist/{chatmaild_filename}"
    )
    remote_path = f"/tmp/{chatmaild_filename}"
    if Path(str(chatmaild_path)).exists():
        files.put(
            name="Upload chatmaild source package",
            src=chatmaild_path.open("rb"),
            dest=remote_path,
        )

        apt.packages(
            name="apt install python3-aiosmtpd",
            packages=["python3-aiosmtpd", "python3-pip"],
        )

        # --no-deps because aiosmtplib is installed with `apt`.
        server.shell(
            name="install chatmaild with pip",
            commands=[f"pip install --break-system-packages {remote_path}"],
        )

        files.put(
            name="upload doveauth-dictproxy.service",
            src=importlib.resources.files("chatmaild")
            .joinpath("doveauth-dictproxy.service")
            .open("rb"),
            dest="/etc/systemd/system/doveauth-dictproxy.service",
            user="root",
            group="root",
            mode="644",
        )
        systemd.service(
            name="Setup doveauth-dictproxy service",
            service="doveauth-dictproxy.service",
            running=True,
            enabled=True,
            restarted=True,
            daemon_reload=True,
        )

        files.put(
            name="upload filtermail.service",
            src=importlib.resources.files("chatmaild")
            .joinpath("filtermail.service")
            .open("rb"),
            dest="/etc/systemd/system/filtermail.service",
            user="root",
            group="root",
            mode="644",
        )
        systemd.service(
            name="Setup filtermail service",
            service="filtermail.service",
            running=True,
            enabled=True,
            restarted=True,
            daemon_reload=True,
        )


def _configure_opendkim(domain: str, dkim_selector: str) -> bool:
    """Configures OpenDKIM"""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("opendkim/opendkim.conf"),
        dest="/etc/opendkim.conf",
        user="root",
        group="root",
        mode="644",
        config={"domain_name": domain, "opendkim_selector": dkim_selector},
    )

    files.directory(
        name="Add opendkim socket directory to /var/spool/postfix",
        path="/var/spool/postfix/opendkim",
        user="opendkim",
        group="opendkim",
        mode="750",
        present=True,
    )

    if not host.get_fact(File, f"/etc/dkimkeys/{dkim_selector}.private"):
        server.shell(
            name="Generate OpenDKIM domain keys",
            commands=[
                f"opendkim-genkey -D /etc/dkimkeys -d {domain} -s {dkim_selector}"
            ],
            _sudo=True,
            _sudo_user="opendkim",
        )

    need_restart |= main_config.changed

    return need_restart


def _configure_postfix(domain: str) -> bool:
    """Configures Postfix SMTP server."""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("postfix/main.cf.j2"),
        dest="/etc/postfix/main.cf",
        user="root",
        group="root",
        mode="644",
        config={"domain_name": domain},
    )
    need_restart |= main_config.changed

    master_config = files.put(
        src=importlib.resources.files(__package__)
        .joinpath("postfix/master.cf")
        .open("rb"),
        dest="/etc/postfix/master.cf",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= master_config.changed

    return need_restart


def _configure_dovecot(mail_server: str) -> bool:
    """Configures Dovecot IMAP server."""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("dovecot/dovecot.conf.j2"),
        dest="/etc/dovecot/dovecot.conf",
        user="root",
        group="root",
        mode="644",
        config={"hostname": mail_server},
    )
    need_restart |= main_config.changed
    auth_config = files.put(
        src=importlib.resources.files(__package__).joinpath("dovecot/auth.conf"),
        dest="/etc/dovecot/auth.conf",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= auth_config.changed

    files.put(
        src=importlib.resources.files(__package__)
        .joinpath("dovecot/expunge.cron")
        .open("rb"),
        dest="/etc/cron.d/expunge",
        user="root",
        group="root",
        mode="644",
    )

    return need_restart


def deploy_chatmail(mail_domain: str, mail_server: str, dkim_selector: str) -> None:
    """Deploy a chat-mail instance.

    :param mail_domain: domain part of your future email addresses
    :param mail_server: the DNS name under which your mail server is reachable
    :param dkim_selector:
    """

    apt.update(name="apt update", cache_time=24 * 3600)
    server.group(name="Create vmail group", group="vmail", system=True)
    server.user(name="Create vmail user", user="vmail", group="vmail", system=True)

    server.group(name="Create opendkim group", group="opendkim", system=True)
    server.user(
        name="Add postfix user to opendkim group for socket access",
        user="postfix",
        groups=["opendkim"],
        system=True,
    )

    # Deploy acmetool to have TLS certificates.
    deploy_acmetool(domains=[mail_server])

    apt.packages(
        name="Install Postfix",
        packages="postfix",
    )

    apt.packages(
        name="Install Dovecot",
        packages=["dovecot-imapd", "dovecot-lmtpd"],
    )

    apt.packages(
        name="Install OpenDKIM",
        packages=[
            "opendkim",
            "opendkim-tools",
        ],
    )

    _install_chatmaild()
    dovecot_need_restart = _configure_dovecot(mail_server)
    postfix_need_restart = _configure_postfix(mail_domain)
    opendkim_need_restart = _configure_opendkim(mail_domain, dkim_selector)

    systemd.service(
        name="Start and enable OpenDKIM",
        service="opendkim.service",
        running=True,
        enabled=True,
        restarted=opendkim_need_restart,
    )

    systemd.service(
        name="Start and enable Postfix",
        service="postfix.service",
        running=True,
        enabled=True,
        restarted=postfix_need_restart,
    )

    systemd.service(
        name="Start and enable Dovecot",
        service="dovecot.service",
        running=True,
        enabled=True,
        restarted=dovecot_need_restart,
    )

    def callback():
        result = server.shell(
            commands=[
                f"""sed 's/\tIN/ 600 IN/;s/\t(//;s/\"$//;s/^\t  \"//g; s/ ).*//' """
                f"""/etc/dkimkeys/{dkim_selector}.txt | tr --delete '\n'"""
            ]
        )
        logger.info(f"Add this TXT entry into DNS zone: {result.stdout}")

    python.call(name="Print TXT entry for DKIM", function=callback)
