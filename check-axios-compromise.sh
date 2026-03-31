#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="${HOME}"
SCAN_NODE_MODULES=1
SCAN_IOC=1
FD_BIN=""
HAVE_RG=0

usage() {
  printf 'Usage: %s [options]\n' "$(basename "$0")"
  printf '\n'
  printf 'Scans lockfiles for known-compromised axios supply-chain versions.\n'
  printf '\n'
  printf 'Options:\n'
  printf '  -r, --root <path>        Root directory to scan (default: $HOME)\n'
  printf '      --skip-node-modules  Skip node_modules checks\n'
  printf '      --skip-ioc           Skip Linux IOC checks\n'
  printf '      --lockfiles-only     Only scan lockfiles\n'
  printf '  -h, --help               Show this help\n'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--root)
      if [[ $# -lt 2 ]]; then
        printf 'Missing value for %s\n' "$1" >&2
        exit 2
      fi
      ROOT_DIR="$2"
      shift 2
      ;;
    --skip-node-modules)
      SCAN_NODE_MODULES=0
      shift
      ;;
    --skip-ioc)
      SCAN_IOC=0
      shift
      ;;
    --lockfiles-only)
      SCAN_NODE_MODULES=0
      SCAN_IOC=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$ROOT_DIR" ]]; then
  printf 'Root path does not exist or is not a directory: %s\n' "$ROOT_DIR" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'python3 is required for this script.\n' >&2
  exit 2
fi

if command -v fd >/dev/null 2>&1; then
  FD_BIN="fd"
elif command -v fdfind >/dev/null 2>&1; then
  FD_BIN="fdfind"
fi

if command -v rg >/dev/null 2>&1; then
  HAVE_RG=1
fi

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED='\033[0;31m'
  C_YELLOW='\033[0;33m'
  C_GREEN='\033[0;32m'
  C_BLUE='\033[0;34m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
else
  C_RED=''
  C_YELLOW=''
  C_GREEN=''
  C_BLUE=''
  C_BOLD=''
  C_RESET=''
fi

critical_count=0
warning_count=0
lockfile_count=0
affected_lockfiles=0
clean_lockfiles=0
node_module_checks=0

print_info() {
  printf '%b[INFO]%b %s\n' "$C_BLUE" "$C_RESET" "$1"
}

print_ok() {
  printf '%b[OK]%b %s\n' "$C_GREEN" "$C_RESET" "$1"
}

print_warn() {
  printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

print_alert() {
  printf '%b[ALERT]%b %s\n' "$C_RED" "$C_RESET" "$1"
}

record_critical() {
  critical_count=$((critical_count + 1))
  print_alert "$1"
}

record_warning() {
  warning_count=$((warning_count + 1))
  print_warn "$1"
}

check_package_and_version() {
  local package_name="$1"
  local package_version="$2"
  local location="$3"

  case "$package_name" in
    axios)
      if [[ "$package_version" == "1.14.1" || "$package_version" == "0.30.4" ]]; then
        record_critical "Compromised axios version found: ${package_name}@${package_version} (${location})"
        return 10
      fi
      ;;
    plain-crypto-js)
      if [[ "$package_version" == "4.2.1" ]]; then
        record_critical "Malicious dependency found: ${package_name}@${package_version} (${location})"
        return 10
      fi
      if [[ -n "$package_version" ]]; then
        record_warning "plain-crypto-js present (${package_name}@${package_version}) at ${location}. Review this installation."
      else
        record_warning "plain-crypto-js present at ${location}. Could not read version."
      fi
      ;;
    @qqbrowser/openclaw-qbot)
      if [[ "$package_version" == "0.0.130" ]]; then
        record_critical "Compromised package found: ${package_name}@${package_version} (${location})"
        return 10
      fi
      ;;
    @shadanai/openclaw)
      if [[ "$package_version" == "2026.3.31-1" || "$package_version" == "2026.3.31-2" ]]; then
        record_critical "Compromised package found: ${package_name}@${package_version} (${location})"
        return 10
      fi
      if [[ -n "$package_version" ]]; then
        record_warning "@shadanai/openclaw present (${package_name}@${package_version}) at ${location}."
      else
        record_warning "@shadanai/openclaw present at ${location}. Could not read version."
      fi
      ;;
  esac

  return 0
}

scan_lockfile() {
  local file_path="$1"
  local parser_output
  local file_critical=0

  if [[ "$HAVE_RG" -eq 1 ]]; then
    if ! rg -q -F \
      -e 'axios' \
      -e 'plain-crypto-js' \
      -e '@qqbrowser/openclaw-qbot' \
      -e '@shadanai/openclaw' \
      -- "$file_path" 2>/dev/null; then
      clean_lockfiles=$((clean_lockfiles + 1))
      return
    fi
  fi

  parser_output="$(python3 - "$file_path" <<'PY'
import json
import os
import re
import sys

path = sys.argv[1]
filename = os.path.basename(path)
seen = set()
target_pkgs = {
    "axios",
    "plain-crypto-js",
    "@qqbrowser/openclaw-qbot",
    "@shadanai/openclaw",
}


def emit(level, pkg, ver, loc):
    key = (level, pkg, ver, loc)
    if key in seen:
        return
    seen.add(key)
    print(f"{level}\t{pkg}\t{ver}\t{loc}")


def check(pkg, ver, loc):
    if not isinstance(ver, str):
        return
    if pkg == "axios" and ver in {"1.14.1", "0.30.4"}:
        emit("CRITICAL", pkg, ver, loc)
    elif pkg == "plain-crypto-js":
        if ver == "4.2.1":
            emit("CRITICAL", pkg, ver, loc)
        else:
            emit("WARNING", pkg, ver, loc)
    elif pkg == "@qqbrowser/openclaw-qbot" and ver == "0.0.130":
        emit("CRITICAL", pkg, ver, loc)
    elif pkg == "@shadanai/openclaw":
        if ver in {"2026.3.31-1", "2026.3.31-2"}:
            emit("CRITICAL", pkg, ver, loc)
        else:
            emit("WARNING", pkg, ver, loc)


def selector_to_name(selector):
    selector = selector.strip().strip('"').strip("'")
    if selector.startswith("npm:"):
        selector = selector[4:]
    if selector.startswith("@"):
        second_at = selector.find("@", 1)
        return selector if second_at < 0 else selector[:second_at]
    first_at = selector.find("@")
    return selector if first_at < 0 else selector[:first_at]


def parse_package_lock(raw):
    try:
        data = json.loads(raw)
    except Exception as exc:
        emit("ERROR", "parse", "", str(exc))
        return

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, value in packages.items():
            if not isinstance(value, dict):
                continue
            ver = value.get("version")
            if not isinstance(key, str):
                continue
            if key == "node_modules/axios" or key.endswith("/node_modules/axios"):
                check("axios", ver, f"packages:{key}")
            elif key == "node_modules/plain-crypto-js" or key.endswith("/node_modules/plain-crypto-js"):
                check("plain-crypto-js", ver, f"packages:{key}")
            elif key == "node_modules/@qqbrowser/openclaw-qbot" or key.endswith("/node_modules/@qqbrowser/openclaw-qbot"):
                check("@qqbrowser/openclaw-qbot", ver, f"packages:{key}")
            elif key == "node_modules/@shadanai/openclaw" or key.endswith("/node_modules/@shadanai/openclaw"):
                check("@shadanai/openclaw", ver, f"packages:{key}")

    def walk(deps, location="dependencies"):
        if not isinstance(deps, dict):
            return
        for name, node in deps.items():
            if not isinstance(node, dict):
                continue
            ver = node.get("version")
            if name in target_pkgs:
                check(name, ver, f"{location}:{name}")
            walk(node.get("dependencies"), f"{location}:{name}/dependencies")

    walk(data.get("dependencies"))


def parse_yarn_lock(raw):
    lines = raw.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or line.startswith(" ") or not stripped.endswith(":"):
            idx += 1
            continue

        selectors = [part.strip() for part in stripped[:-1].split(",")]
        names = set()
        for selector in selectors:
            name = selector_to_name(selector)
            if name in target_pkgs:
                names.add(name)

        version = ""
        j = idx + 1
        while j < len(lines):
            sub = lines[j]
            sub_stripped = sub.strip()
            if not sub_stripped:
                break
            if not sub.startswith(" "):
                break
            m = re.match(r"version(?:\\s+|:\\s*)\"?([^\"\\s]+)\"?", sub_stripped)
            if m:
                version = m.group(1)
                break
            j += 1

        if names and version:
            for name in names:
                check(name, version, f"line:{idx + 1}")
        idx = j if j > idx else idx + 1


def parse_text_lock(raw):
    lines = raw.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for pkg in target_pkgs:
            m = re.search(rf"{re.escape(pkg)}@(?:npm:)?([0-9]+\\.[0-9]+\\.[0-9]+[0-9A-Za-z.+-]*)", line)
            if m:
                check(pkg, m.group(1), f"line:{line_no}")


try:
    if filename == "package-lock.json":
        with open(path, "r", encoding="utf-8") as f:
            parse_package_lock(f.read())
    elif filename == "yarn.lock":
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            parse_yarn_lock(f.read())
    elif filename in {"bun.lock", "bun.lockb"}:
        with open(path, "rb") as f:
            parse_text_lock(f.read().decode("utf-8", errors="ignore"))
except Exception as exc:
    emit("ERROR", "scan", "", str(exc))
PY
)"

  if [[ -z "$parser_output" ]]; then
    clean_lockfiles=$((clean_lockfiles + 1))
    return
  fi

  while IFS=$'\t' read -r level pkg version location; do
    [[ -z "$level" ]] && continue
    case "$level" in
      CRITICAL)
        check_package_and_version "$pkg" "$version" "$file_path ($location)"
        file_critical=1
        ;;
      WARNING)
        check_package_and_version "$pkg" "$version" "$file_path ($location)"
        ;;
      ERROR)
        record_warning "Could not fully parse ${file_path}: ${location}"
        ;;
    esac
  done <<< "$parser_output"

  if [[ "$file_critical" -eq 1 ]]; then
    affected_lockfiles=$((affected_lockfiles + 1))
  fi
}

list_lockfiles() {
  if [[ -n "$FD_BIN" ]]; then
    "$FD_BIN" -0 --hidden --no-ignore-vcs --type f --full-path \
      '(package-lock\.json|yarn\.lock|bun\.lock|bun\.lockb)$' "$ROOT_DIR" \
      --exclude .git \
      --exclude node_modules \
      --exclude .cache \
      --exclude .npm \
      --exclude .pnpm-store \
      --exclude .yarn \
      --exclude .bun 2>/dev/null
    return
  fi

  find "$ROOT_DIR" \
    -type d \( -name .git -o -name node_modules -o -name .cache -o -name .npm -o -name .pnpm-store -o -name .yarn -o -name .bun \) -prune -o \
    -type f \( -name package-lock.json -o -name yarn.lock -o -name bun.lock -o -name bun.lockb \) -print0 2>/dev/null
}

list_target_node_package_jsons() {
  if [[ -n "$FD_BIN" ]]; then
    "$FD_BIN" -0 --hidden --no-ignore-vcs --type d '^node_modules$' "$ROOT_DIR" \
      --exclude .git \
      --exclude .cache \
      --exclude .npm \
      --exclude .pnpm-store \
      --exclude .yarn \
      --exclude .bun 2>/dev/null
    return
  fi

  find "$ROOT_DIR" \
    -type d \( -name .git -o -name .cache -o -name .npm -o -name .pnpm-store -o -name .yarn -o -name .bun \) -prune -o \
    -type d -name node_modules -print0 2>/dev/null
}

scan_lockfiles() {
  print_info "Scanning lockfiles under: ${ROOT_DIR}"

  while IFS= read -r -d '' lockfile; do
    lockfile_count=$((lockfile_count + 1))
    scan_lockfile "$lockfile"
  done < <(list_lockfiles)

  if [[ "$lockfile_count" -eq 0 ]]; then
    record_warning "No lockfiles found under ${ROOT_DIR}."
  else
    print_info "Scanned ${lockfile_count} lockfile(s)."
  fi
}

read_name_version() {
  local json_file="$1"

  python3 - "$json_file" <<'PY'
import json
import sys

path = sys.argv[1]
name = ""
version = ""

try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    name = data.get("name", "")
    version = data.get("version", "")
except Exception:
    pass

print(f"{name}\t{version}")
PY
}

scan_node_modules() {
  print_info "Scanning node_modules for installed artifacts under: ${ROOT_DIR}"

  local node_modules_dirs=0

  while IFS= read -r -d '' node_modules_dir; do
    node_modules_dirs=$((node_modules_dirs + 1))

    local pkg
    for pkg in "axios" "plain-crypto-js" "@qqbrowser/openclaw-qbot" "@shadanai/openclaw"; do
      local pkg_dir="${node_modules_dir}/${pkg}"
      local pkg_json="${pkg_dir}/package.json"

      if [[ ! -d "$pkg_dir" ]]; then
        continue
      fi

      if [[ "$pkg" == "plain-crypto-js" && ! -f "$pkg_json" ]]; then
        record_warning "Found ${pkg_dir} without package.json (unexpected layout)."
        continue
      fi

      if [[ ! -f "$pkg_json" ]]; then
        continue
      fi

      node_module_checks=$((node_module_checks + 1))

      local parsed
      local pkg_name
      local pkg_version

      parsed="$(read_name_version "$pkg_json")"
      pkg_name="${parsed%%$'\t'*}"
      pkg_version="${parsed#*$'\t'}"

      if [[ -z "$pkg_name" ]]; then
        record_warning "Could not read package metadata: ${pkg_json}"
        continue
      fi

      check_package_and_version "$pkg_name" "$pkg_version" "$pkg_json"
    done
  done < <(list_target_node_package_jsons)

  print_info "Visited ${node_modules_dirs} node_modules directory(ies)."
  print_info "Checked ${node_module_checks} package artifact(s) under node_modules."
}

scan_iocs_linux() {
  print_info "Running Linux IOC checks"

  if [[ -f "/tmp/ld.py" ]]; then
    record_critical "IOC found: /tmp/ld.py exists"
  else
    print_ok "No /tmp/ld.py IOC file found"
  fi

  local proc_hits=""
  if command -v pgrep >/dev/null 2>&1; then
    proc_hits="$(pgrep -af '(^|/)ld\.py([[:space:]]|$)|sfrclak\.com|142\.11\.206\.73' 2>/dev/null || true)"
  else
    if [[ "$HAVE_RG" -eq 1 ]]; then
      proc_hits="$(ps -eo pid,args 2>/dev/null | rg '(^|/)ld\.py([[:space:]]|$)|sfrclak\.com|142\.11\.206\.73' || true)"
    else
      proc_hits="$(ps -eo pid,args 2>/dev/null | grep -E '(^|/)ld\.py([[:space:]]|$)|sfrclak\.com|142\.11\.206\.73' | grep -v grep || true)"
    fi
  fi

  if [[ -n "$proc_hits" ]]; then
    record_critical "Potential malicious process indicators found"
    printf '%s\n' "$proc_hits"
  else
    print_ok "No suspicious process matches found"
  fi

  local net_hits=""
  if command -v ss >/dev/null 2>&1; then
    if [[ "$HAVE_RG" -eq 1 ]]; then
      net_hits="$(ss -tunp 2>/dev/null | rg -F '142.11.206.73' || true)"
    else
      net_hits="$(ss -tunp 2>/dev/null | grep -F '142.11.206.73' || true)"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if [[ "$HAVE_RG" -eq 1 ]]; then
      net_hits="$(netstat -tunp 2>/dev/null | rg -F '142.11.206.73' || true)"
    else
      net_hits="$(netstat -tunp 2>/dev/null | grep -F '142.11.206.73' || true)"
    fi
  fi

  if [[ -n "$net_hits" ]]; then
    record_critical "Active network connection to IOC IP 142.11.206.73 found"
    printf '%s\n' "$net_hits"
  else
    print_ok "No active connection to IOC IP 142.11.206.73 found"
  fi
}

print_info "Axios compromise scan starting"
print_info "Root: ${ROOT_DIR}"

scan_lockfiles

if [[ "$SCAN_NODE_MODULES" -eq 1 ]]; then
  scan_node_modules
else
  print_info "Skipping node_modules checks"
fi

if [[ "$SCAN_IOC" -eq 1 ]]; then
  if [[ "$(uname -s)" == "Linux" ]]; then
    scan_iocs_linux
  else
    record_warning "IOC checks are Linux-specific. Current OS: $(uname -s)"
  fi
else
  print_info "Skipping IOC checks"
fi

printf '\n'
printf '%bScan Summary%b\n' "$C_BOLD" "$C_RESET"
printf '  Root scanned: %s\n' "$ROOT_DIR"
printf '  Lockfiles scanned: %s\n' "$lockfile_count"
printf '  Lockfiles with critical findings: %s\n' "$affected_lockfiles"
printf '  Critical findings: %s\n' "$critical_count"
printf '  Warnings: %s\n' "$warning_count"

if [[ "$critical_count" -gt 0 ]]; then
  printf '\n'
  printf '%bResult: POTENTIAL EXPOSURE FOUND%b\n' "$C_RED" "$C_RESET"
  printf 'Recommended next steps:\n'
  printf '  1) Isolate affected machine(s) and stop new installs.\n'
  printf '  2) Revoke and rotate secrets used on affected hosts.\n'
  printf '  3) Review CI/build logs from 2026-03-31 00:21-03:29 UTC.\n'
  printf '  4) Rebuild compromised environments from known-clean images.\n'
  exit 1
fi

if [[ "$warning_count" -gt 0 ]]; then
  printf '\n'
  printf '%bResult: NO CRITICAL IOC FOUND, BUT REVIEW WARNINGS%b\n' "$C_YELLOW" "$C_RESET"
  exit 0
fi

printf '\n'
printf '%bResult: no known indicators found%b\n' "$C_GREEN" "$C_RESET"
exit 0
