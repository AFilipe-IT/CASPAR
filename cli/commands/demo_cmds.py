"""
cli/commands/demo_cmds.py — `caspar demo`: write example configurations to disk.

A Docker install has no repository, so the fixtures under test_target/ are out
of reach for exactly the people most likely to want them: someone evaluating
CASPAR for the first time. This command carries a small set of them inside the
package so `caspar demo` produces something worth scanning on any install.

The configurations are deliberately realistic rather than minimal — a
three-line file scores a number but demonstrates nothing about what the tool
sees in a real deployment. Each vulnerable file has a hardened counterpart, so
the pair can be scanned and diffed to show a score moving for a known reason.
"""

from __future__ import annotations

from pathlib import Path

import click

# ── Apache ─────────────────────────────────────────────────────────────

_APACHE_VULNERABLE = """\
# Apache HTTP Server — deliberately vulnerable example (CASPAR demo).
# Every setting below is a real misconfiguration found in the CIS Apache
# HTTP Server 2.4 Benchmark. Do not deploy this.

ServerRoot "/etc/apache2"
Listen 80
Listen 443

# Information disclosure: version and OS in every response header and error
# page. Individually low impact; together they form an attack chain.
ServerTokens Full
ServerSignature On

# Cross-Site Tracing: TRACE reflects request headers, including cookies.
TraceEnable On

# Runs as a privileged user: a compromise of any module becomes root.
User root
Group root

# Directory listing and symlink following: exposes files never meant to be
# served and allows escaping the document root.
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

# No request limits: trivially abusable for denial of service.
Timeout 300
KeepAliveTimeout 60

# Weak TLS: SSLv3 and RC4 are broken (POODLE, BEAST).
<VirtualHost *:443>
    SSLEngine on
    SSLProtocol +SSLv3 +TLSv1
    SSLCipherSuite RC4-SHA:AES128-SHA
</VirtualHost>

ErrorLog ${APACHE_LOG_DIR}/error.log
"""

_APACHE_HARDENED = """\
# Apache HTTP Server — hardened counterpart of apache-vulnerable.conf.
# Same service, same features, every finding addressed.

ServerRoot "/etc/apache2"
Listen 80
Listen 443

# Minimal disclosure: product name only, no signature on error pages.
ServerTokens Prod
ServerSignature Off

TraceEnable Off

# Unprivileged service account.
User www-data
Group www-data

<Directory "/var/www/html">
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Bounded request handling.
Timeout 60
KeepAliveTimeout 5

<VirtualHost *:443>
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4
    Header always set Strict-Transport-Security "max-age=63072000"
    Header always append Content-Security-Policy "frame-ancestors 'self'"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>

ErrorLog ${APACHE_LOG_DIR}/error.log
"""

# ── NGINX ──────────────────────────────────────────────────────────────

_NGINX_VULNERABLE = """\
# NGINX — deliberately vulnerable example (CASPAR demo).
# Based on the CIS NGINX Benchmark v3.0.0. Do not deploy this.

user root;
worker_processes auto;
error_log /var/log/nginx/error.log;

events {
    worker_connections 1024;
}

http {
    # Version disclosure in headers and error pages.
    server_tokens on;

    # No security headers at all: no CSP, no HSTS, no frame protection.

    server {
        listen 80;
        listen 443 ssl;
        server_name _;

        # Broken TLS: SSLv3 and TLS 1.0 are deprecated and exploitable.
        ssl_protocols SSLv3 TLSv1 TLSv1.1;
        ssl_ciphers ALL:!aNULL;

        # Directory listing exposes files never intended to be served.
        location / {
            root /var/www/html;
            autoindex on;
        }

        # Reverse proxy with no upstream certificate verification: any
        # machine on the path can impersonate the backend.
        location /api/ {
            proxy_pass https://backend.internal:8443/;
        }
    }
}
"""

_NGINX_HARDENED = """\
# NGINX — hardened counterpart of nginx-vulnerable.conf.

user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    server {
        listen 80;
        listen 443 ssl;
        server_name _;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            root /var/www/html;
            autoindex off;
        }

        location /api/ {
            proxy_pass https://backend.internal:8443/;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        }
    }
}
"""

_FILES = {
    "apache-vulnerable.conf": _APACHE_VULNERABLE,
    "apache-hardened.conf": _APACHE_HARDENED,
    "nginx-vulnerable.conf": _NGINX_VULNERABLE,
    "nginx-hardened.conf": _NGINX_HARDENED,
}


@click.command("demo")
@click.option("-o", "--output", "outdir", default="caspar-demo",
              type=click.Path(file_okay=False),
              show_default=True,
              help="Directory to write the example configurations into.")
@click.option("--force", is_flag=True,
              help="Overwrite files that already exist.")
def demo(outdir: str, force: bool) -> None:
    """Write example configurations to scan.

    \b
    Produces four files — a vulnerable and a hardened version of an Apache and
    an NGINX configuration — so a fresh install has something realistic to
    assess without cloning the repository:

      caspar demo
      caspar scan caspar-demo/apache-vulnerable.conf

    \b
    Scanning the pair shows what the score is measuring:

      caspar scan caspar-demo/apache-vulnerable.conf --report -f json -o before
      caspar scan caspar-demo/apache-hardened.conf   --report -f json -o after
      caspar diff before/*.json after/*.json
    """
    target = Path(outdir)
    target.mkdir(parents=True, exist_ok=True)

    written, skipped = [], []
    for name, content in _FILES.items():
        path = target / name
        if path.exists() and not force:
            skipped.append(name)
            continue
        path.write_text(content, encoding="utf-8")
        written.append(name)

    click.echo()
    for name in written:
        click.echo(f"  {click.style('created', fg='green')}  {target / name}")
    for name in skipped:
        click.echo(f"  {click.style('exists', fg='yellow')}   {target / name}"
                   f"  (use --force to overwrite)")

    if not written:
        click.echo()
        return

    click.echo()
    click.echo("  These are deliberately insecure configurations, for "
               "assessment only.")
    click.echo("  Never deploy them.")
    click.echo()
    click.echo("  Next:")
    click.echo(f"    caspar scan {target}/apache-vulnerable.conf")
    click.echo(f"    caspar scan {target}/nginx-vulnerable.conf")
    click.echo()
    click.echo("  Compare against the hardened versions to see the score move:")
    click.echo(f"    caspar scan {target}/apache-hardened.conf")
    click.echo()
