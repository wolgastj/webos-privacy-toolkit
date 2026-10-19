import argparse
import json
from pathlib import Path
import re
import subprocess

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DEFAULT_DOMAINS = Path(__file__).resolve().parent.parent / "data" / "domains.txt"

def parse_domains(text):
    domains = set()
    for raw in text.splitlines():
        value = raw.split("#", 1)[0].strip().lower()
        if not value:
            continue
        if not HOST_RE.fullmatch(value):
            raise ValueError(f"Invalid domain: {value!r}")
        domains.add(value)
    return sorted(domains)

def blocklist(args):
    domains = parse_domains(Path(args.input).read_text())
    if args.format == "dnsmasq":
        output = "".join(f"address=/{d}/0.0.0.0\n" for d in domains)
    else:
        output = "".join(d + "\n" for d in domains)
    write_output(args.output, output)

def analyze(args):
    domains = parse_domains(Path(args.domains).read_text())
    observed = {}
    for line in Path(args.input).read_text().splitlines():
        for domain in domains:
            if re.search(r"(?<![a-zA-Z0-9.-])" + re.escape(domain) + r"(?![a-zA-Z0-9.-])", line, re.I):
                observed[domain] = observed.get(domain, 0) + 1
    write_output(args.output, json.dumps({"matched_queries": observed}, indent=2) + "\n")

COMMANDS = {
    "system": "uname -a; cat /etc/os-release 2>/dev/null || true",
    "processes": "ps 2>/dev/null || true",
    "hosts": "cat /etc/hosts 2>/dev/null || true",
    "sockets": "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true",
}
def inspect(args):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", args.host):
        raise ValueError("Invalid host")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]*", args.user):
        raise ValueError("Invalid user")
    result = {}
    for name, command in COMMANDS.items():
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "ConnectTimeout=5", f"{args.user}@{args.host}", command],
            capture_output=True, text=True, timeout=20, check=False)
        result[name] = {"exit_code": proc.returncode, "stdout": proc.stdout,
                        "stderr": proc.stderr}
    write_output(args.output, json.dumps(result, indent=2) + "\n")

def write_output(path, content):
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    else:
        print(content, end="")

def main():
    parser = argparse.ArgumentParser(description="webOS privacy audit helpers")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("blocklist")
    b.add_argument("--input", default=str(DEFAULT_DOMAINS))
    b.add_argument("--format", choices=["plain", "dnsmasq"], default="plain")
    b.add_argument("--output")
    b.set_defaults(func=blocklist)
    a = sub.add_parser("analyze")
    a.add_argument("--input", required=True)
    a.add_argument("--domains", default=str(DEFAULT_DOMAINS))
    a.add_argument("--output")
    a.set_defaults(func=analyze)
    i = sub.add_parser("inspect")
    i.add_argument("--host", required=True)
    i.add_argument("--user", default="root")
    i.add_argument("--output")
    i.set_defaults(func=inspect)
    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
