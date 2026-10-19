# webOS Privacy Toolkit

A conservative, auditable toolkit for inspecting and reducing LG webOS network telemetry **on TVs you own**.

This project does not root your TV, bypass firmware protections, or claim to eliminate all telemetry. It provides:
- An editable DNS blocklist template for use with your router or DNS resolver (empty by default).
- A read-only SSH diagnostic collector for already-rooted webOS TVs.
- A local report parser for DNS query logs.
- Unit tests and CI.

## Quick start

Python 3.10+; no third-party runtime dependencies. Run from the repository root.

```sh
git clone https://github.com/wolgastj/webos-privacy-toolkit.git
cd webos-privacy-toolkit
python3 -m unittest discover -s tests -v
python3 -m webos_privacy blocklist --output build/lg-domains.txt
python3 -m webos_privacy analyze --input examples/dns.log --domains examples/observed-domains.txt
python3 -m webos_privacy inspect --host 192.168.1.50 --user root
```

`inspect` requires existing authorized SSH access; it does not attempt to obtain root.
Review the commands before using them. It never changes TV settings.

## DNS blocklist

`data/domains.txt` is deliberately empty: no LG endpoints are blocked out of the box.
The domains in `examples/` are synthetic fixtures, not actual LG telemetry endpoints.
Check your own DNS logs before enabling blocks.
Start with the minimum necessary and add observed hosts to `data/domains.txt`.
The `blocklist` command removes comments, validates hostnames and deduplicates entries.
It emits one hostname per line, suitable for many DNS denylist importers.

For dnsmasq:
```sh
python3 -m webos_privacy blocklist --format dnsmasq --output build/lg-dnsmasq.conf
# Review, then include in your dnsmasq config and reload dnsmasq.
```

The generator only writes configuration; it does not install or activate it.
The initial dnsmasq output redirects IPv4 A records only; it is **not** a complete
IPv6 or non-A-record blocking policy. Review resolver-specific behavior before use.

Blocking names can break apps, account login, updates and ThinQ. Name-based
blocking cannot prevent direct-IP connections, hardcoded resolvers, or new endpoints.

## Log analysis

The sample analysis command returns:

```json
{
  "matched_queries": {
    "telemetry.example.com": 1
  }
}
```

Despite the historical field name `matched_queries`, values count **log lines**
containing each exact hostname, case-insensitively, at most once per line. This is
not a DNS-protocol parser: replies can count, subdomains are not expanded, and no
allow/block decision is inferred. It is a triage helper, not proof of privacy.

## Read-only inspection

```sh
python3 -m webos_privacy inspect --host tv.lan --user root --output build/inspection.json
```

The collector queries `uname`, `/etc/os-release`, running processes,
`/etc/hosts` and available TCP/UDP sockets. It uses the local `ssh` binary,
requires pre-established trust, enforces BatchMode, and does not disable services.
Hostnames and IPv4 literals are accepted; IPv6 SSH destinations are not yet supported.
The output preserves each SSH exit code and stderr; inspect those fields for failures.
Optional commands that are unavailable may yield empty output. SSH failure does not
currently make the overall CLI exit nonzero, so do not use its exit status as a
privacy or connectivity assertion.
The output may include IP addresses, hostnames, and process details: treat as private.

## Rooting and optional OS-level controls

Rooting compatibility depends on the exact model and firmware. Research first:
- https://cani.rootmy.tv/
- https://github.com/webosbrew/webos-homebrew-channel
- https://github.com/rorygallagher2024/glasshouse

For supported rooted TVs, Glasshouse provides privacy controls and persistent
overlays. Use its own documentation rather than copying unknown service names
or altering read-only system partitions. Back up settings first.

## Validation methodology

1. Baseline DNS queries and outbound flows while idle, watching HDMI, streaming,
   and in standby.
2. Turn off LG Live Plus/ACR and advertising personalization in TV settings.
3. Apply a reviewed DNS denylist at your resolver.
4. Repeat measurements after reboot and compare; capture IPv4 and IPv6.
5. Confirm firmware updates, streaming apps and other features still work.

Absence of DNS queries does **not** prove absence of network telemetry.

## Security

Never expose SSH or third-party TV management dashboards to the Internet.
Use SSH keys and known_hosts verification. Do not put credentials in command lines,
source files or committed logs. Only inspect devices you administer.

## Development

```sh
python3 -m unittest discover -s tests -v
```

Tests exercise local parsing, rendering, error handling, and mocked SSH calls.
They do not establish compatibility with any specific TV or firmware. This initial
release has not been hardware-tested and does not automate OS-level modifications.

## License

MIT. See LICENSE.
