# WiFiLeverage

Proves whether your wireless segmentation actually holds — from a client's foothold, the way an attacker on the guest network would.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square)
![modules](https://img.shields.io/badge/modules-4-informational?style=flat-square)

## What it does

Segmentation is a control you're told is in place: the guest SSID is walled off from the corporate VLAN, the IoT network can't see the workstations, one tenant can't reach another. WiFiLeverage tests that claim instead of trusting it.

From a single associated client it maps the wireless surface, works out exactly which segment DHCP dropped you on, and then probes whether the networks that are *supposed* to be isolated from that foothold are actually reachable. A host you can reach across a boundary that was meant to isolate it is the finding. A boundary that refuses every probe is recorded as evidence the control works.

Everything is passive by default — enumerating networks and reading your own host's addressing sends nothing beyond a normal Wi-Fi scan. Active probing (cross-segment reachability and client-isolation testing) only runs when you ask for it with `--active`, and every packet is filtered through your engagement scope first.

## Why you'd use it

- Turns "segmentation is configured" into a tested result with evidence
- Cross-segment reachability and client/AP isolation checks from a real foothold
- Scope-aware — include/exclude rules mean excluded networks are never probed
- Unprivileged: TCP-connect probing, no raw sockets or root required
- Degrades gracefully — uses `nmcli`/`iw`/`ip` when present, skips cleanly when not
- JSON + Markdown reports you can drop straight into an engagement writeup
- Standard library only, one dependency (PyYAML)

## Install

```bash
git clone https://github.com/CypherNova1337/WiFiLeverage
cd WiFiLeverage
pip install .
```

Requires Python 3.9+. For development:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

**List the access points in range (passive):**

```bash
wifileverage scan --iface wlan0
```

**Map your foothold and check cross-segment reach (standard profile):**

```bash
wifileverage run --iface wlan0 --active -S scope.yaml
```

**Passive only — map the surface, send no probes:**

```bash
wifileverage run --iface wlan0 -p passive
```

**Deep run — reachability and client-isolation testing:**

```bash
wifileverage run --iface wlan0 --active -p deep -S scope.yaml
```

**Define scope inline instead of a file:**

```bash
wifileverage run --iface wlan0 --active \
  -i 10.20.0.0/16 -i 192.168.50.0/24 -x 10.20.9.0/24
```

**Verify the effective scope before you probe anything:**

```bash
wifileverage scope -S scope.yaml -x 10.20.9.0/24
```

**Target specific modules and ports:**

```bash
wifileverage run --iface wlan0 --active --only reach --ports 22,80,443,445,3389
wifileverage modules
```

## Commands

| Command | Purpose |
|---|---|
| `run` | Run a segmentation assessment (passive by default) |
| `scan` | Passive wireless recon only — list in-range access points |
| `scope` | Load and display the effective scope without probing |
| `modules` | List available modules and their phase |

### Key run options

| Flag | Default | Description |
|---|---|---|
| `--iface` | auto | Wireless/network interface to assess |
| `--active` | **off** | Enable active probing (`reach`, `isolation`) |
| `-p` / `--profile` | `standard` | `passive`, `standard`, `deep` |
| `--phases` | — | Comma-separated phases: `passive`, `active` |
| `--only` | — | Comma-separated module names |
| `-S` / `--scope` | — | Scope file (YAML) |
| `-i` / `-x` | — | Add an in-scope / out-of-scope CIDR (repeatable) |
| `--ssid` | — | Restrict to an SSID (repeatable) |
| `--ports` | `22,80,443,445,3389,8080` | TCP ports for connect probes |
| `--timeout` | `1.5` | Per-probe timeout (seconds) |
| `--host-limit` | `256` | Max hosts enumerated per target CIDR |
| `-o` / `--output` | `reports/` | Directory for JSON/Markdown reports |
| `--no-save` | off | Print to stdout only |

## Modules

| Module | Phase | What it checks |
|---|---|---|
| `recon` | passive | In-range APs, their security, in-scope SSIDs |
| `segment` | passive | Local subnet, gateway, DNS, ARP neighbours — your foothold |
| `reach` | active | Reachability to in-scope hosts **across** segment boundaries |
| `isolation` | active | Whether same-SSID peer stations can reach each other |

## How scope works

Scope is a convenience, not a wall — `run` works without one — but on a real engagement you should always define it. List the segment you expect to land on *and* the one it should be isolated from; `reach` tests the gap between them. Anything under `exclude_cidrs` is never touched, even if it falls inside a target range. See [`examples/scope.example.yaml`](examples/scope.example.yaml).

## Important considerations

- `--active` is the line between reading the airwaves/your own host and sending probes to other hosts — know which side you're on before you run.
- `reach` only probes targets **outside** your current subnet; put both the guest and the corporate ranges in scope so there's a boundary to test.
- Probing is unprivileged TCP connect by default; results reflect what a normal client can reach, which is exactly the attacker model that matters for segmentation.
- A clean run (no cross-segment reach) is a *result*, not a failure — it's evidence the control works, and it's recorded as such.

## Authorized use

This tool is for authorized security testing only. Only point it at wireless networks and hosts you own or have explicit, written permission to assess. Active probing interacts with other systems on the network, and doing that without authorization may be illegal in your jurisdiction. The scope controls are there to help you stay inside an agreed engagement — use them.

## License

MIT — see [LICENSE](LICENSE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
