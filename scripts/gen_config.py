#!/usr/bin/env python3
"""Gera nginx.conf sintético com N server blocks (misto seguro/inseguro) para §5.1."""
import argparse
import random


def gen_server_block(i: int, insecure: bool) -> str:
    autoindex = "on" if insecure else "off"
    server_tokens = "on" if insecure else "off"
    ssl_protocols = "TLSv1 TLSv1.1" if insecure else "TLSv1.2 TLSv1.3"
    return f"""
    server {{
        listen {8000 + i};
        server_name site{i}.example.com;
        root /var/www/site{i};
        index index.html;

        autoindex {autoindex};
        server_tokens {server_tokens};

        location / {{
            try_files $uri $uri/ =404;
        }}

        location /api{i}/ {{
            proxy_pass http://127.0.0.1:{9000 + i};
            ssl_protocols {ssl_protocols};
        }}
    }}
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="nginx")
    ap.add_argument("--blocks", type=int, required=True, help="numero de server blocks a gerar")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)
    blocks = [gen_server_block(i, insecure=random.random() < 0.5) for i in range(args.blocks)]

    print("worker_processes  1;")
    print("events { worker_connections 1024; }")
    print("http {")
    print("    include       mime.types;")
    print("    default_type  application/octet-stream;")
    print("    sendfile on;")
    print("    keepalive_timeout 65;")
    for b in blocks:
        print(b)
    print("}")


if __name__ == "__main__":
    main()
