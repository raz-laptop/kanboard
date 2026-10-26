#!/usr/bin/env python3
"""
php2shell attack-SIGNATURE simulator (detection / control-validation harness).

PURPOSE
    Validate that a blocking layer (WAF, nginx rules, runtime sensor, ...) catches
    php2shell-style traffic. It reproduces the *request shape* the attack uses —
    malformed multipart/RFC-1867 uploads that drive PHP's session.upload_progress
    code path (the vulnerable precondition for CVE-2026-109618 / 109619) — and
    reports, per target, whether the request was BLOCKED or REACHED THE SERVER.

WHAT THIS IS NOT
    This is NOT an exploit. It contains no memory-corruption, use-after-free,
    memory-disclosure or code-execution payload. It only generates attack-shaped
    requests so you can measure whether a control stops them. For a real PoC, use
    the vendor/Wiz write-up inside your isolated lab.

USE ONLY against hosts you own and are authorized to test (here: your own
IP-restricted EC2 demo box). Point it at the unprotected and protected
containers to show the difference.
"""
import argparse
import socket
import ssl
import sys
import uuid


def build_upload_progress_body(boundary, name_prefix, variant):
    """Craft a multipart body that activates/abuses session.upload_progress.

    The field named by PHP's session.upload_progress.name (default
    'PHP_SESSION_UPLOAD_PROGRESS') must appear BEFORE the file part for PHP to
    begin progress tracking — that is the code path php2shell abuses. We vary the
    field/value shapes a detector would flag. No exploit payload is included.
    """
    nl = "\r\n"
    # 'malformed' inflates field name/value sizes to look like the abuse pattern;
    # 'basic' is just a well-formed upload-progress request.
    key = "PHP_SESSION_UPLOAD_PROGRESS"
    if variant == "malformed":
        progress_val = "A" * 4096          # oversized progress key value
        extra_name = "x" * 1024            # oversized field name
    else:
        progress_val = "demo-" + uuid.uuid4().hex
        extra_name = "note"

    parts = []
    parts.append(f"--{boundary}{nl}")
    parts.append(
        f'Content-Disposition: form-data; name="{key}"{nl}{nl}{progress_val}{nl}'
    )
    parts.append(f"--{boundary}{nl}")
    parts.append(
        f'Content-Disposition: form-data; name="{extra_name}"{nl}{nl}marker{nl}'
    )
    parts.append(f"--{boundary}{nl}")
    parts.append(
        f'Content-Disposition: form-data; name="file"; '
        f'filename="upload.bin"{nl}'
        f"Content-Type: application/octet-stream{nl}{nl}"
    )
    parts.append("0" * 2048)               # benign file bytes, no payload
    parts.append(nl)
    parts.append(f"--{boundary}--{nl}")
    return "".join(parts).encode("latin-1", "ignore")


def send_once(host, port, use_tls, path, variant, timeout):
    """Return (verdict, detail). Verdict in {BLOCKED, REACHED, ERROR}."""
    boundary = "----php2shelldemo" + uuid.uuid4().hex[:12]
    body = build_upload_progress_body(boundary, "PHP_SESSION_UPLOAD_PROGRESS", variant)
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-sim/validation\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + body

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = raw
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.sendall(req)
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
    except (ConnectionResetError, ConnectionAbortedError) as e:
        return "BLOCKED", f"connection reset ({e.__class__.__name__})"
    except (socket.timeout, TimeoutError):
        return "BLOCKED", "timed out (dropped by a control?)"
    except OSError as e:
        return "ERROR", f"{e}"

    if not data:
        return "BLOCKED", "empty response / closed before reply"
    status_line = data.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
    code = status_line.split(" ")[1] if " " in status_line else "?"
    if code in ("403", "406", "429", "444", "503"):
        return "BLOCKED", status_line
    return "REACHED", status_line


def main():
    ap = argparse.ArgumentParser(description="php2shell attack-signature simulator (not an exploit)")
    ap.add_argument("target", nargs="?", default="http://127.0.0.1:8080",
                    help="base URL, e.g. http://127.0.0.1:8080")
    ap.add_argument("-n", "--count", type=int, default=5, help="requests to send")
    ap.add_argument("--path", default="/index.php", help="request path")
    ap.add_argument("--variant", choices=["basic", "malformed", "both"], default="both")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    use_tls = args.target.startswith("https://")
    rest = args.target.split("://", 1)[-1].rstrip("/")
    host, _, port_s = rest.partition(":")
    port = int(port_s) if port_s else (443 if use_tls else 80)

    variants = ["basic", "malformed"] if args.variant == "both" else [args.variant]
    print(f"Target {args.target}{args.path}  ({args.count} req, variants={variants})")
    print("-" * 60)

    tally = {"BLOCKED": 0, "REACHED": 0, "ERROR": 0}
    for i in range(args.count):
        variant = variants[i % len(variants)]
        verdict, detail = send_once(host, port, use_tls, args.path, variant, args.timeout)
        tally[verdict] += 1
        print(f"[{i+1:>2}] {variant:<9} {verdict:<8} {detail}")

    print("-" * 60)
    print(f"Summary: {tally['REACHED']} reached server, "
          f"{tally['BLOCKED']} blocked, {tally['ERROR']} errors")
    if tally["REACHED"] and not tally["BLOCKED"]:
        print("=> Nothing stopped the attack-shaped traffic (unprotected target).")
    elif tally["BLOCKED"] and not tally["REACHED"]:
        print("=> A control blocked all attack-shaped traffic (protected target).")
    else:
        print("=> Mixed result — inspect which variants got through.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
