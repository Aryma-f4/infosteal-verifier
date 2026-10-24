<div align="center">

# infosteal-verifier

**Fast native credential verifier for admin panels & CMS targets**

[![Latest Release](https://img.shields.io/github/v/release/Aryma-f4/infosteal-verifier?style=flat-square&label=release&color=12eb90)](https://github.com/Aryma-f4/infosteal-verifier/releases/latest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Aryma-f4/infosteal-verifier/release.yml?style=flat-square&label=build)](https://github.com/Aryma-f4/infosteal-verifier/actions)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success?style=flat-square)](#why-zero-dependencies)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue?style=flat-square)](https://github.com/Aryma-f4/infosteal-verifier/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f?style=flat-square)](LICENSE)

**[⬇ Download v1.1.0](https://github.com/Aryma-f4/infosteal-verifier/releases/tag/v1.1.0)**

</div>

---

## Overview

`infosteal-verifier` takes a list of `url + username:password` pairs and reports which of them
still authenticate against **admin panels, control panels and CMS login forms** — WordPress,
cPanel, Plesk, phpMyAdmin, WHM, Jira, Confluence, Synology DSM, ownCloud, Magento and more.

It is a **native** tool: written in Rust with **zero third-party crates**, a native **Cocoa/AppKit
desktop GUI** on macOS, and a headless CLI everywhere else. There is no Python, no virtualenv, no
`.NET` runtime, and no Electron bundle.

---

## Why zero dependencies

| Layer | Choice | Reason |
|---|---|---|
| HTTP / SOCKS | `/usr/bin/curl` via `std::process` | Ships with macOS, every mainstream Linux image, and Windows 10+. Gives TLS, HTTP/2, proxy and cookie-jar support for free. |
| Desktop GUI | Direct Objective-C runtime FFI → `AppKit.framework` | A real native macOS window — no browser, no WebView, no HTML. |
| Threading | `std::thread` + `std::sync::atomic` | No async runtime tax. |
| Everything else | `std` | No supply-chain surface. |

Result: a ~1 MB static binary, sub-second cold start, and nothing to install.

---

## ✨ Features

- **14 panel / CMS detectors** with panel-specific login flows (not just a password POST):
  WordPress · phpMyAdmin · WHM · cPanel · Plesk · PrestaShop · Adminer · Joomla · Magento ·
  Atlassian Confluence · Atlassian Jira · RDWeb · Synology DSM (QuickConnect) · ownCloud
- **CSRF / token handling** per panel — `form_key`, `requesttoken`, `forgery_protection_token`,
  `security_token`, `wsidchk`, PHP session tokens, `PLESKSESSID`, `pmaAuth`, `wordpress_logged_in`.
- **Plesk JSFuck challenge solver** — decodes the `var west=…; east=…` obfuscated integer used by
  Plesk's pre-login gate.
- **cPanel domain enumeration** — after a successful login it walks
  `/execute/DomainInfo/domains_data` and lists the hosted domains.
- **Synology QuickConnect resolver** — resolves `global.quickconnect.to` tunnels, then logs in via
  `SYNO.API.Auth`.
- **Proxy support** — HTTP, SOCKS4, SOCKS5, per-request auth, round-robin rotation across workers.
- **Concurrency** — 1…500 workers, live throughput graph, ETA, per-panel result files.
- **Native macOS desktop GUI** — dark Aqua theme, `NSOpenPanel` pickers, real-time chart.
- **cPanel/Jira/Confluence style JSON responses** are parsed, not regex-guessed.

---

## 📦 Install

Grab a prebuilt binary from the [releases page](https://github.com/Aryma-f4/infosteal-verifier/releases).

### macOS (native desktop GUI)

```bash
unzip infosteal-verifier-macos-aarch64.zip      # Apple Silicon
unzip infosteal-verifier-macos-x86_64.zip       # Intel
open AdminPanel.app
```

### Linux (static, no libc dependency)

```bash
tar -xzf infosteal-verifier-linux-x86_64.tar.gz
./infosteal-verifier --help
```

### Windows

```powershell
Expand-Archive infosteal-verifier-windows-x86_64.zip
.\infosteal-verifier.exe --help
```

---

## 🖥 Usage

### GUI (macOS)

```bash
infosteal-verifier
```

Opens the native window:

- **Resources** — `Accounts | N` and `Proxies | N` buttons open the macOS file picker.
- **Settings** — `HTTP / Socks4 / Socks5` segmented control, thread count, proxy-list URL.
- **Statistic** — valid / invalid / error counters, `accs/min`, elapsed, ETA, live throughput
  chart and a progress bar.
- **Start / Stop** — starts the run; **Results** opens the output folder in Finder.

### CLI (all platforms)

```bash
infosteal-verifier \
  --accounts accounts.txt \
  --proxies  proxies.txt \
  --proxy-type socks5 \
  --threads 150
```

| Flag | Description |
|---|---|
| `-a, --accounts <file>` | Account list. Enables headless mode. |
| `-p, --proxies <file>` | Proxy list (`host:port` or `host:port:user:pass`). |
| `-u, --proxy-url <url>` | Fetch the proxy list from a URL. |
| `-t, --proxy-type <type>` | `Http` \| `Socks4` \| `Socks5` (default `Http`). |
| `-c, --threads <1..500>` | Concurrent workers (default `150`). |
| `--parse-only` | Validate the account list and print a breakdown, without any request. |
| `--preload <file>` | macOS GUI: open the window with an account list already loaded. |
| `--self-test` | Run the built-in verification suite. |

---

## 📄 Input formats

**Accounts** — every one of these layouts is accepted:

```
# scheme-less (how credential dumps are usually shaped)
host.tld/path:user:pass
host.tld:8443/path:user:pass

# with scheme, colon separated
https://host.tld/path:user:pass
https://host.tld:8443/path:user:pass

# with scheme, space separated
https://host.tld/path user:pass
```

- The scheme may be omitted; it defaults to `https://` and the request is
  retried over `http://` when the TLS attempt cannot connect.
- A port inside the target stays with the target.
- The password may itself contain `:` and spaces.
- A leading `://` that is not a real scheme (`chrome://`, `android://`, …) is
  reported as `Invalid` rather than being requested.
- Loopback and RFC1918 targets are skipped as `Invalid`.

**Proxies** — one per line:

```
1.2.3.4:8080
5.6.7.8:1080:user:pass
```

### Validating a list before a run

Large dumps are worth checking first. `--parse-only` loads the file, reports
how many lines are usable targets and how they break down, then exits without
sending a single request:

```bash
infosteal-verifier --accounts dump.txt --parse-only
```

```
lines read      : 3495706
usable targets  : 3476221
rejected        : 19485
  https (implicit)     3476220
  http                 1
```

The file is streamed rather than read into memory, so a 227 MB / 3.5 million
line dump loads in a few seconds and a few hundred megabytes of RAM.

---

## 📊 Output

Everything lands in `./Results/run_<timestamp> - <n> bases/`:

| File | Meaning |
|---|---|
| `Good_<Panel>.txt` | Credentials that authenticated successfully. |
| `Bad_<Panel>.txt` | Credentials rejected by that panel. |
| `Unknown.txt` | Panel not recognised. |
| `Invalid.txt` | Malformed, over-length (32) or private/loopback target. |
| `CantCheck.txt` | Network failure after 5 retries. |
| `Error.txt` | Failure details. |
| `Remains.txt` | Unprocessed entries when a run is stopped early. |

---

## 🛠 Build from source

```bash
git clone https://github.com/Aryma-f4/infosteal-verifier.git
cd infosteal-verifier

cargo build --release                      # native host
cargo run --release -- --self-test         # verification suite

# cross targets
rustup target add x86_64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-apple-darwin
cargo build --release --target x86_64-unknown-linux-musl
```

Linux `aarch64` static builds use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild):

```bash
cargo install cargo-zigbuild --locked
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

Release binaries for every platform are produced by the
[release workflow](.github/workflows/release.yml).

---

## 🔬 Provenance & what was removed

This implementation was reconstructed from the behaviour of a ConfuserEx-packed Windows
`PE/CLI` "Admin Panel Checker" (`.NET Framework 4.8`, WPF + HandyControl + LiveCharts +
Costura.Fody packing).

That original binary carried two things this rewrite **deliberately does not have**:

| Original component | Detail | Status here |
|---|---|---|
| **License C2 channel** | `TcpClient` → `199.247.29.156:1337`, `SslStream` handshake with issuer pinning (`Cloudflare, Inc.`), length-prefixed `JObject` framing, `{"method":"checkLicense","software":…,"version":…,"hwid":…}` request. The app refused to start if the channel failed. | **Removed** |
| **Hardware fingerprint collector** (`Mint.Hwid`) | Queried 8 WMI hardware classes (`SELECT … FROM Win32_*`, USB/PCI/CPU/Disk/BIOS), read the Windows SID, and shipped the hash to the C2. Also wrote `HKEY_CURRENT_USER\Software\MintEngine\*` registry state. | **Removed** |

Everything else — the panel detection heuristics, the per-panel login flows, the token/cookie
handling, the Plesk JSFuck solver, the cPanel domain enumeration, the Synology QuickConnect
resolver, the result-file layout — was re-implemented from observed behaviour.

The result is a tool that talks to **only the targets you give it**, stores results **only
locally**, and has **no telemetry, no persistence, and no remote control**.

---

## ⚠️ Authorized use only

This tool is for **security testing of systems you own or have explicit written permission to
test** — authorised penetration tests, red-team exercises, bug-bounty validation, and audits of
your own infrastructure.

Running it against third-party systems without authorisation is illegal in most jurisdictions
(Computer Fraud and Abuse Act, UK Computer Misuse Act, Indonesian UU ITE / UU 24, etc.) and may
violate the target's terms of service. Use rate limits that respect the target's infrastructure.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 👤 Author

**Aryma-f4** — <https://github.com/Aryma-f4>
