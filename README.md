# check-axios-compromise

A fast local scanner for the March 31, 2026 Axios npm supply-chain incident.

It scans lockfiles, optionally checks `node_modules`, and runs Linux IOC checks for known indicators tied to the malicious Axios releases.

## What this script checks

### Lockfiles

- `package-lock.json`
- `yarn.lock`
- `bun.lock`
- `bun.lockb` (best-effort text parsing)

The script looks for:

- `axios@1.14.1` (compromised)
- `axios@0.30.4` (compromised)
- `plain-crypto-js@4.2.1` (malicious dependency)
- `@qqbrowser/openclaw-qbot@0.0.130` (related compromised package)
- `@shadanai/openclaw@2026.3.31-1` and `@shadanai/openclaw@2026.3.31-2` (related compromised versions)

### `node_modules` artifacts (optional, enabled by default)

Scans discovered `node_modules` directories for installed copies of:

- `axios`
- `plain-crypto-js`
- `@qqbrowser/openclaw-qbot`
- `@shadanai/openclaw`

### Linux IOC checks (optional, enabled by default)

- File IOC: `/tmp/ld.py`
- Process matches containing `ld.py`, `sfrclak.com`, or `142.11.206.73`
- Active network connections to `142.11.206.73`

## Requirements

- `bash`
- `python3`

Optional (used automatically for speed):

- `fd` or `fdfind`
- `rg` (ripgrep)

## Usage

```bash
./check-axios-compromise.sh [options]
```

Options:

- `-r, --root <path>`: root directory to scan (default: `$HOME`)
- `--skip-node-modules`: skip installed package checks
- `--skip-ioc`: skip IOC checks
- `--lockfiles-only`: scan only lockfiles
- `-h, --help`: show help

## Examples

Scan your full home directory:

```bash
./check-axios-compromise.sh
```

Scan a specific directory:

```bash
./check-axios-compromise.sh --root "/path/to/projects"
```

Only check lockfiles:

```bash
./check-axios-compromise.sh --lockfiles-only
```

## Exit codes

- `0`: no critical findings (warnings may still exist)
- `1`: critical finding detected (potential exposure)
- `2`: invalid usage or missing required dependency

## Output interpretation

- `[ALERT]`: critical hit (treat as potential compromise)
- `[WARN]`: non-critical but suspicious or incomplete data
- `[OK]`: check passed
- `[INFO]`: progress information

At the end, the script prints a summary with lockfile count, critical findings, and warnings.

## Limitations

- Detects known indicators only; it is not a full malware forensics tool.
- IOC checks are Linux-specific.
- `bun.lockb` is parsed as text best-effort and may miss edge cases.
- Deep historical compromise analysis still requires CI logs, endpoint telemetry, and credential audit.

## If you get a critical finding

Recommended immediate actions:

1. Isolate affected machine(s).
2. Revoke and rotate credentials used on those hosts.
3. Review CI/build logs for `2026-03-31 00:21-03:29 UTC`.
4. Rebuild affected environments from known-clean images.

## Reference

- Snyk write-up: `https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/`
