#!/usr/bin/env bash
#
# rmp self-updater.
#
# Checks the latest GitHub release of RMP and, if a newer version exists,
# downloads the matching binary for this platform and installs it.
#
# Usage:
#   update.sh            # check and, if newer, prompt to install
#   update.sh --check    # only report whether an update is available
#   update.sh --force    # reinstall even if already up to date
#   update.sh --yes      # do not prompt (for automation)
#
# Env:
#   RMP_REPO         override the GitHub repo (default: marcosgabrielgomes110-collab/rmp)
#   RMP_INSTALL_DIR  where to install the binary (default: /usr/local/bin)
#
set -euo pipefail

REPO="${RMP_REPO:-marcosgabrielgomes110-collab/rmp}"
INSTALL_DIR="${RMP_INSTALL_DIR:-/usr/local/bin}"
BIN="${INSTALL_DIR}/rmp"
API="https://api.github.com/repos/${REPO}/releases/latest"

CHECK_ONLY=0
FORCE=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --force) FORCE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "opção desconhecida: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "erro: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl não encontrado"

# --- current version ---------------------------------------------------------
# The install target is always $INSTALL_DIR/rmp. For reading the *current*
# version we may fall back to a `rmp` found on PATH (informational only).
CUR=""
if [ -x "$BIN" ]; then
  CUR="$("$BIN" --version 2>/dev/null | awk '{print $NF}')"
elif found="$(command -v rmp 2>/dev/null)"; then
  CUR="$("$found" --version 2>/dev/null | awk '{print $NF}')"
fi
CUR="${CUR:-none}"

# --- latest release ----------------------------------------------------------
LATEST_JSON="$(curl -fsSL -H 'User-Agent: rmp-update' "$API")" \
  || die "não foi possível consultar a API do GitHub (rede? rate limit?)"
LATEST="$(printf '%s' "$LATEST_JSON" \
  | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
  | head -n1 \
  | sed -E 's/.*"v?([^"]+)"$/\1/')"
[ -n "$LATEST" ] || die "não encontrei a tag do release mais recente"

# is LATEST strictly greater than CUR?
newer() {
  [ "$1" = "$2" ] && return 1
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$2" ]
}

if ! newer "$CUR" "$LATEST"; then
  echo "rmp está atualizado (instalado: ${CUR}; mais recente: ${LATEST})."
  exit 0
fi

echo "Nova versão disponível: ${CUR} -> ${LATEST}"
[ "$CHECK_ONLY" -eq 1 ] && exit 0

# --- platform asset ----------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  target="x86_64-unknown-linux-gnu"; ext="tar.gz" ;;
  Darwin)
    if [ "$arch" = "arm64" ]; then target="aarch64-apple-darwin"; else
      die "sem build para macOS ${arch} (apenas arm64)"
    fi
    ext="tar.gz" ;;
  MINGW*|MSYS*|CYGWIN*) target="x86_64-pc-windows-msvc"; ext="zip" ;;
  *) die "sistema não suportado: ${os}" ;;
esac

asset="rmp-v${LATEST}-${target}.${ext}"
url="https://github.com/${REPO}/releases/download/v${LATEST}/${asset}"

# --- confirm -----------------------------------------------------------------
if [ "$FORCE" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  printf 'Instalar %s em %s? [Y/n] ' "$asset" "$BIN"
  read -r answer
  case "$answer" in [nN]*) echo "cancelado."; exit 0 ;; esac
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Baixando ${asset}..."
curl -fsSL -o "$tmp/$asset" "$url" || die "download falhou: $url"

# --- extract -----------------------------------------------------------------
if [ "$ext" = "tar.gz" ]; then
  tar -xzf "$tmp/$asset" -C "$tmp"
  newbin="$(find "$tmp" -type f -name rmp -not -name '*.exe' | head -n1)"
else
  command -v unzip >/dev/null 2>&1 || die "unzip não encontrado"
  unzip -oq "$tmp/$asset" -d "$tmp"
  newbin="$(find "$tmp" -type f -name 'rmp.exe' | head -n1)"
fi
[ -n "${newbin:-}" ] && [ -f "$newbin" ] || die "não encontrei o binário no pacote"

# sanity check: the new binary must run and report the expected version
chmod +x "$newbin"
got="$("$newbin" --version 2>/dev/null | awk '{print $NF}' || true)"
[ "$got" = "$LATEST" ] || die "binário baixado reporta '${got}', esperado '${LATEST}'"

# --- install -----------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  install -m0755 "$newbin" "$BIN"
else
  command -v sudo >/dev/null 2>&1 || die "sem permissão em ${INSTALL_DIR} e sem sudo"
  sudo install -m0755 "$newbin" "$BIN"
fi

echo "Atualizado: $("$BIN" --version)  (em $BIN)"
