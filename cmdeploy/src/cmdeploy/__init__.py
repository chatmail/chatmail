"""
Chat Mail pyinfra deploy.
"""

import importlib.resources
import io
import shutil
import subprocess
import sys
from pathlib import Path

from chatmaild.config import Config, read_config
from pyinfra import facts, host
from pyinfra.facts.files import File
from pyinfra.facts.systemd import SystemdEnabled
from pyinfra.operations import apt, files, pip, server, systemd

from .acmetool import deploy_acmetool


def _build_chatmaild(dist_dir) -> None:
    dist_dir = Path(dist_dir).resolve()
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir()
    subprocess.check_output(
        [sys.executable, "-m", "build", "-n"]
        + ["--sdist", "chatmaild", "--outdir", str(dist_dir)]
    )
    entries = list(dist_dir.iterdir())
    assert len(entries) == 1
    return entries[0]


def remove_legacy_artifacts():
    # disable legacy doveauth-dictproxy.service
    if host.get_fact(SystemdEnabled).get("doveauth-dictproxy.service"):
        systemd.service(
            name="Disable legacy doveauth-dictproxy.service",
            service="doveauth-dictproxy.service",
            running=False,
            enabled=False,
        )


def _install_remote_venv_with_chatmaild(config) -> None:
    remove_legacy_artifacts()
    dist_file = _build_chatmaild(dist_dir=Path("chatmaild/dist"))
    remote_base_dir = "/usr/local/lib/chatmaild"
    remote_dist_file = f"{remote_base_dir}/dist/{dist_file.name}"
    remote_venv_dir = f"{remote_base_dir}/venv"
    remote_chatmail_inipath = f"{remote_base_dir}/chatmail.ini"
    root_owned = dict(user="root", group="root", mode="644")

    apt.packages(
        name="apt install python3-virtualenv",
        packages=["python3-virtualenv"],
    )

    files.put(
        name="Upload chatmaild source package",
        src=dist_file.open("rb"),
        dest=remote_dist_file,
        create_remote_dir=True,
        **root_owned,
    )

    files.put(
        name=f"Upload {remote_chatmail_inipath}",
        src=config._getbytefile(),
        dest=remote_chatmail_inipath,
        **root_owned,
    )

    pip.virtualenv(
        name=f"chatmaild virtualenv {remote_venv_dir}",
        path=remote_venv_dir,
        always_copy=True,
    )

    apt.packages(
        name="install gcc and headers to build crypt_r source package",
        packages=["gcc", "python3-dev"],
    )

    server.shell(
        name=f"forced pip-install {dist_file.name}",
        commands=[
            f"{remote_venv_dir}/bin/pip install --force-reinstall {remote_dist_file}"
        ],
    )

    files.template(
        src=importlib.resources.files(__package__).joinpath("metrics.cron.j2"),
        dest="/etc/cron.d/chatmail-metrics",
        user="root",
        group="root",
        mode="644",
        config={
            "mailboxes_dir": config.mailboxes_dir,
            "execpath": f"{remote_venv_dir}/bin/chatmail-metrics",
        },
    )

    # install systemd units
    for fn in (
        "doveauth",
        "filtermail",
        "echobot",
        "chatmail-metadata",
        "lastlogin",
    ):
        params = dict(
            execpath=f"{remote_venv_dir}/bin/{fn}",
            config_path=remote_chatmail_inipath,
            remote_venv_dir=remote_venv_dir,
            mail_domain=config.mail_domain,
        )
        source_path = importlib.resources.files(__package__).joinpath(
            "service", f"{fn}.service.f"
        )
        content = source_path.read_text().format(**params).encode()

        files.put(
            name=f"Upload {fn}.service",
            src=io.BytesIO(content),
            dest=f"/etc/systemd/system/{fn}.service",
            **root_owned,
        )
        systemd.service(
            name=f"Setup {fn} service",
            service=f"{fn}.service",
            running=True,
            enabled=True,
            restarted=True,
            daemon_reload=True,
        )


def _configure_opendkim(domain: str, dkim_selector: str = "dkim") -> bool:
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
    need_restart |= main_config.changed

    screen_script = files.put(
        src=importlib.resources.files(__package__).joinpath("opendkim/screen.lua"),
        dest="/etc/opendkim/screen.lua",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= screen_script.changed

    final_script = files.put(
        src=importlib.resources.files(__package__).joinpath("opendkim/final.lua"),
        dest="/etc/opendkim/final.lua",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= final_script.changed

    files.directory(
        name="Add opendkim directory to /etc",
        path="/etc/opendkim",
        user="opendkim",
        group="opendkim",
        mode="750",
        present=True,
    )

    keytable = files.template(
        src=importlib.resources.files(__package__).joinpath("opendkim/KeyTable"),
        dest="/etc/dkimkeys/KeyTable",
        user="opendkim",
        group="opendkim",
        mode="644",
        config={"domain_name": domain, "opendkim_selector": dkim_selector},
    )
    need_restart |= keytable.changed

    signing_table = files.template(
        src=importlib.resources.files(__package__).joinpath("opendkim/SigningTable"),
        dest="/etc/dkimkeys/SigningTable",
        user="opendkim",
        group="opendkim",
        mode="644",
        config={"domain_name": domain, "opendkim_selector": dkim_selector},
    )
    need_restart |= signing_table.changed
    files.directory(
        name="Add opendkim socket directory to /var/spool/postfix",
        path="/var/spool/postfix/opendkim",
        user="opendkim",
        group="opendkim",
        mode="750",
        present=True,
    )

    apt.packages(
        name="apt install opendkim opendkim-tools",
        packages=["opendkim", "opendkim-tools"],
    )

    if not host.get_fact(File, f"/etc/dkimkeys/{dkim_selector}.private"):
        server.shell(
            name="Generate OpenDKIM domain keys",
            commands=[
                f"/usr/sbin/opendkim-genkey -D /etc/dkimkeys -d {domain} -s {dkim_selector}"
            ],
            _use_su_login=True,
            _su_user="opendkim",
        )

    service_file = files.put(
        name="Configure opendkim to restart once a day",
        src=importlib.resources.files(__package__).joinpath("opendkim/systemd.conf"),
        dest="/etc/systemd/system/opendkim.service.d/10-prevent-memory-leak.conf",
    )
    need_restart |= service_file.changed


    return need_restart


def _uninstall_mta_sts_daemon() -> None:
    # Remove configuration.
    files.file("/etc/mta-sts-daemon.yml", present=False)

    files.directory("/usr/local/lib/postfix-mta-sts-resolver", present=False)

    files.file("/etc/systemd/system/mta-sts-daemon.service", present=False)

    systemd.service(
        name="Stop MTA-STS daemon",
        service="mta-sts-daemon.service",
        daemon_reload=True,
        running=False,
        enabled=False,
    )


def _configure_postfix(config: Config, debug: bool = False) -> bool:
    """Configures Postfix SMTP server."""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("postfix/main.cf.j2"),
        dest="/etc/postfix/main.cf",
        user="root",
        group="root",
        mode="644",
        config=config,
        disable_ipv6=config.disable_ipv6,
    )
    need_restart |= main_config.changed

    master_config = files.template(
        src=importlib.resources.files(__package__).joinpath("postfix/master.cf.j2"),
        dest="/etc/postfix/master.cf",
        user="root",
        group="root",
        mode="644",
        debug=debug,
        config=config,
    )
    need_restart |= master_config.changed

    header_cleanup = files.put(
        src=importlib.resources.files(__package__).joinpath(
            "postfix/submission_header_cleanup"
        ),
        dest="/etc/postfix/submission_header_cleanup",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= header_cleanup.changed

    # Login map that 1:1 maps email address to login.
    login_map = files.put(
        src=importlib.resources.files(__package__).joinpath("postfix/login_map"),
        dest="/etc/postfix/login_map",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= login_map.changed

    return need_restart


def _configure_dovecot(config: Config, debug: bool = False) -> bool:
    """Configures Dovecot IMAP server."""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("dovecot/dovecot.conf.j2"),
        dest="/etc/dovecot/dovecot.conf",
        user="root",
        group="root",
        mode="644",
        config=config,
        debug=debug,
        disable_ipv6=config.disable_ipv6,
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
    lua_push_notification_script = files.put(
        src=importlib.resources.files(__package__).joinpath(
            "dovecot/push_notification.lua"
        ),
        dest="/etc/dovecot/push_notification.lua",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= lua_push_notification_script.changed

    files.template(
        src=importlib.resources.files(__package__).joinpath("dovecot/expunge.cron.j2"),
        dest="/etc/cron.d/expunge",
        user="root",
        group="root",
        mode="644",
        config=config,
    )

    # as per https://doc.dovecot.org/configuration_manual/os/
    # it is recommended to set the following inotify limits
    for name in ("max_user_instances", "max_user_watches"):
        key = f"fs.inotify.{name}"
        server.sysctl(
            name=f"Change {key}",
            key=key,
            value=65535,
            persist=True,
        )

    return need_restart


def _configure_nginx(config: Config, debug: bool = False) -> bool:
    """Configures nginx HTTP server."""
    need_restart = False

    main_config = files.template(
        src=importlib.resources.files(__package__).joinpath("nginx/nginx.conf.j2"),
        dest="/etc/nginx/nginx.conf",
        user="root",
        group="root",
        mode="644",
        config={"domain_name": config.mail_domain},
        disable_ipv6=config.disable_ipv6,
    )
    need_restart |= main_config.changed

    autoconfig = files.template(
        src=importlib.resources.files(__package__).joinpath("nginx/autoconfig.xml.j2"),
        dest="/var/www/html/.well-known/autoconfig/mail/config-v1.1.xml",
        user="root",
        group="root",
        mode="644",
        config={"domain_name": config.mail_domain},
    )
    need_restart |= autoconfig.changed

    mta_sts_config = files.template(
        src=importlib.resources.files(__package__).joinpath("nginx/mta-sts.txt.j2"),
        dest="/var/www/html/.well-known/mta-sts.txt",
        user="root",
        group="root",
        mode="644",
        config={"domain_name": config.mail_domain},
    )
    need_restart |= mta_sts_config.changed

    # install CGI newemail script
    #
    cgi_dir = "/usr/lib/cgi-bin"
    files.directory(
        name=f"Ensure {cgi_dir} exists",
        path=cgi_dir,
        user="root",
        group="root",
    )

    files.put(
        name="Upload cgi newemail.py script",
        src=importlib.resources.files("chatmaild").joinpath("newemail.py").open("rb"),
        dest=f"{cgi_dir}/newemail.py",
        user="root",
        group="root",
        mode="755",
    )

    return need_restart


def _remove_rspamd() -> None:
    """Remove rspamd"""
    apt.packages(name="Remove rspamd", packages="rspamd", present=False)


def check_config(config):
    mail_domain = config.mail_domain
    if mail_domain != "testrun.org" and not mail_domain.endswith(".testrun.org"):
        blocked_words = "merlinux schmieder testrun.org".split()
        for key in config.__dict__:
            value = config.__dict__[key]
            if key.startswith("privacy") and any(
                x in str(value) for x in blocked_words
            ):
                raise ValueError(
                    f"please set your own privacy contacts/addresses in {config._inipath}"
                )
    return config


def deploy_mtail(config):
    apt.packages(
        name="Install mtail",
        packages=["mtail"],
    )

    # Using our own systemd unit instead of `/usr/lib/systemd/system/mtail.service`.
    # This allows to read from journalctl instead of log files.
    files.template(
        src=importlib.resources.files(__package__).joinpath("mtail/mtail.service.j2"),
        dest="/etc/systemd/system/mtail.service",
        user="root",
        group="root",
        mode="644",
        address=config.mtail_address or "127.0.0.1",
        port=3903,
    )

    mtail_conf = files.put(
        name="Mtail configuration",
        src=importlib.resources.files(__package__).joinpath(
            "mtail/delivered_mail.mtail"
        ),
        dest="/etc/mtail/delivered_mail.mtail",
        user="root",
        group="root",
        mode="644",
    )

    systemd.service(
        name="Start and enable mtail",
        service="mtail.service",
        running=bool(config.mtail_address),
        enabled=bool(config.mtail_address),
        restarted=mtail_conf.changed,
    )


def deploy_iroh_relay(config) -> None:
    (url, sha256sum) = {
        "x86_64": (
            "https://github.com/n0-computer/iroh/releases/download/v0.28.1/iroh-relay-v0.28.1-x86_64-unknown-linux-musl.tar.gz",
            "2ffacf7c0622c26b67a5895ee8e07388769599f60e5f52a3bd40a3258db89b2c",
        ),
        "aarch64": (
            "https://github.com/n0-computer/iroh/releases/download/v0.28.1/iroh-relay-v0.28.1-aarch64-unknown-linux-musl.tar.gz",
            "b915037bcc1ff1110cc9fcb5de4a17c00ff576fd2f568cd339b3b2d54c420dc4",
        ),
    }[host.get_fact(facts.server.Arch)]

    apt.packages(
        name="Install curl",
        packages=["curl"],
    )

    server.shell(
        name="Download iroh-relay",
        commands=[
            f"(echo '{sha256sum} /usr/local/bin/iroh-relay' | sha256sum -c) || (curl -L {url} | gunzip | tar -x -f - ./iroh-relay -O >/usr/local/bin/iroh-relay.new && mv /usr/local/bin/iroh-relay.new /usr/local/bin/iroh-relay)",
            "chmod 755 /usr/local/bin/iroh-relay",
        ],
    )

    need_restart = False

    systemd_unit = files.put(
        name="Upload iroh-relay systemd unit",
        src=importlib.resources.files(__package__).joinpath("iroh-relay.service"),
        dest="/etc/systemd/system/iroh-relay.service",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= systemd_unit.changed

    iroh_config = files.put(
        name="Upload iroh-relay config",
        src=importlib.resources.files(__package__).joinpath("iroh-relay.toml"),
        dest="/etc/iroh-relay.toml",
        user="root",
        group="root",
        mode="644",
    )
    need_restart |= iroh_config.changed

    systemd.service(
        name="Start and enable iroh-relay",
        service="iroh-relay.service",
        running=True,
        enabled=config.enable_iroh_relay,
        restarted=need_restart,
    )


def deploy_chatmail(config_path: Path, disable_mail: bool) -> None:
    """Deploy a chat-mail instance.

    :param config_path: path to chatmail.ini
    :param disable_mail: whether to disable postfix & dovecot
    """
    config = read_config(config_path)
    check_config(config)
    mail_domain = config.mail_domain

    from .www import build_webpages

    server.group(name="Create vmail group", group="vmail", system=True)
    server.user(name="Create vmail user", user="vmail", group="vmail", system=True)
    server.user(name="Create filtermail user", user="filtermail", system=True)
    server.group(name="Create opendkim group", group="opendkim", system=True)
    server.user(
        name="Create opendkim user",
        user="opendkim",
        groups=["opendkim"],
        system=True,
    )
    server.user(
        name="Add postfix user to opendkim group for socket access",
        user="postfix",
        groups=["opendkim"],
        system=True,
    )
    server.user(name="Create echobot user", user="echobot", system=True)
    server.user(name="Create iroh user", user="iroh", system=True)

    # Add our OBS repository for dovecot_no_delay
    files.put(
        name="Add Deltachat OBS GPG key to apt keyring",
        src=importlib.resources.files(__package__).joinpath("obs-home-deltachat.gpg"),
        dest="/etc/apt/keyrings/obs-home-deltachat.gpg",
        user="root",
        group="root",
        mode="644",
    )

    files.line(
        name="Add DeltaChat OBS home repository to sources.list",
        path="/etc/apt/sources.list",
        line="deb [signed-by=/etc/apt/keyrings/obs-home-deltachat.gpg] https://download.opensuse.org/repositories/home:/deltachat/Debian_12/ ./",
        escape_regex_characters=True,
        ensure_newline=True,
    )

    files.line(
        name="Add 9.9.9.9 to resolv.conf",
        path="/etc/resolv.conf",
        line="nameserver 9.9.9.9",
    )
    apt.update(name="apt update", cache_time=24 * 3600)
    apt.upgrade(name="upgrade apt packages", auto_remove=True)

    apt.packages(
        name="Install rsync",
        packages=["rsync"],
    )

    # Run local DNS resolver `unbound`.
    # `resolvconf` takes care of setting up /etc/resolv.conf
    # to use 127.0.0.1 as the resolver.
    apt.packages(
        name="Install unbound",
        packages=["unbound", "unbound-anchor", "dnsutils"],
    )
    server.shell(
        name="Generate root keys for validating DNSSEC",
        commands=[
            "unbound-anchor -a /var/lib/unbound/root.key || true",
            "systemctl reset-failed unbound.service",
        ],
    )
    systemd.service(
        name="Start and enable unbound",
        service="unbound.service",
        running=True,
        enabled=True,
    )

    deploy_iroh_relay(config)

    # Deploy acmetool to have TLS certificates.
    tls_domains = [mail_domain, f"mta-sts.{mail_domain}", f"www.{mail_domain}"]
    deploy_acmetool(
        domains=tls_domains,
    )

    apt.packages(
        # required for setfacl for echobot
        name="Install acl",
        packages="acl",
    )

    apt.packages(
        name="Install Postfix",
        packages="postfix",
    )

    apt.packages(
        name="Install Dovecot",
        packages=["dovecot-imapd", "dovecot-lmtpd"],
    )

    apt.packages(
        name="Install nginx",
        packages=["nginx", "libnginx-mod-stream"],
    )

    apt.packages(
        name="Install fcgiwrap",
        packages=["fcgiwrap"],
    )

    www_path = importlib.resources.files(__package__).joinpath("../../../www").resolve()

    build_dir = www_path.joinpath("build")
    src_dir = www_path.joinpath("src")
    build_webpages(src_dir, build_dir, config)
    files.rsync(f"{build_dir}/", "/var/www/html", flags=["-avz"])

    _install_remote_venv_with_chatmaild(config)
    debug = False
    dovecot_need_restart = _configure_dovecot(config, debug=debug)
    postfix_need_restart = _configure_postfix(config, debug=debug)
    nginx_need_restart = _configure_nginx(config)
    _uninstall_mta_sts_daemon()

    _remove_rspamd()
    opendkim_need_restart = _configure_opendkim(mail_domain, "opendkim")

    systemd.service(
        name="Start and enable OpenDKIM",
        service="opendkim.service",
        running=True,
        enabled=True,
        daemon_reload=opendkim_need_restart,
        restarted=opendkim_need_restart,
    )

    # Dovecot should be started before Postfix
    # because it creates authentication socket
    # required by Postfix.
    systemd.service(
        name="disable dovecot for now" if disable_mail else "Start and enable Dovecot",
        service="dovecot.service",
        running=False if disable_mail else True,
        enabled=False if disable_mail else True,
        restarted=dovecot_need_restart if not disable_mail else False,
    )

    systemd.service(
        name="disable postfix for now" if disable_mail else "Start and enable Postfix",
        service="postfix.service",
        running=False if disable_mail else True,
        enabled=False if disable_mail else True,
        restarted=postfix_need_restart if not disable_mail else False,
    )

    systemd.service(
        name="Start and enable nginx",
        service="nginx.service",
        running=True,
        enabled=True,
        restarted=nginx_need_restart,
    )

    # This file is used by auth proxy.
    # https://wiki.debian.org/EtcMailName
    server.shell(
        name="Setup /etc/mailname",
        commands=[f"echo {mail_domain} >/etc/mailname; chmod 644 /etc/mailname"],
    )

    journald_conf = files.put(
        name="Configure journald",
        src=importlib.resources.files(__package__).joinpath("journald.conf"),
        dest="/etc/systemd/journald.conf",
        user="root",
        group="root",
        mode="644",
    )
    systemd.service(
        name="Start and enable journald",
        service="systemd-journald.service",
        running=True,
        enabled=True,
        restarted=journald_conf.changed,
    )
    files.directory(
        name="Ensure old logs on disk are deleted",
        path="/var/log/journal/",
        present=False,
    )

    apt.packages(
        name="Ensure cron is installed",
        packages=["cron"],
    )

    deploy_mtail(config)
