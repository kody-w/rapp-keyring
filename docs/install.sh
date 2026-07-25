#!/usr/bin/env bash
#
# RAPP Keyring installer.
#
#   curl -fsSL https://kody-w.github.io/rapp-keyring/install.sh | bash
#
# Installs one Python file and a small shim into ~/.local/bin. No root, no
# system service, no package manager, no network access after this script ends.
#
set -euo pipefail

REPO="kody-w/rapp-keyring"
RAW="https://raw.githubusercontent.com/${REPO}/main"
PREFIX="${RAPP_KEYRING_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
LIB="$PREFIX/lib/rapp-keyring"

say()  { printf '  %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

printf '\nRAPP Keyring — on-device credential broker for AI agents\n\n'

# ---- preflight -------------------------------------------------------------

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.8 or newer."

PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
python3 - <<'EOF' || die "Python 3.8 or newer is required (found $PYV)."
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
EOF
say "python3 $PYV"

if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  die "neither curl nor wget is available"
fi

# ---- fetch -----------------------------------------------------------------

mkdir -p "$LIB" "$BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading rapp_keyring.py"
$FETCH "$RAW/rapp_keyring.py" > "$TMP/rapp_keyring.py" || die "download failed"
$FETCH "$RAW/VERSION"         > "$TMP/VERSION"         || echo "0.0.0" > "$TMP/VERSION"

# A truncated download must not become a working-looking install.
python3 -c "
import ast,sys
src = open('$TMP/rapp_keyring.py').read()
ast.parse(src)
assert 'def cmd_run' in src and 'class Redactor' in src, 'file is incomplete'
" || die "downloaded file is incomplete or corrupt — refusing to install"

VERSION="$(cat "$TMP/VERSION")"
say "verified rapp_keyring.py (version $VERSION)"

install -m 0644 "$TMP/rapp_keyring.py" "$LIB/rapp_keyring.py"
install -m 0644 "$TMP/VERSION"         "$LIB/VERSION"

cat > "$BIN/rapp-keyring" <<EOF
#!/usr/bin/env bash
exec python3 "$LIB/rapp_keyring.py" "\$@"
EOF
chmod 0755 "$BIN/rapp-keyring"
say "installed $BIN/rapp-keyring"

# ---- prove it runs ---------------------------------------------------------

if ! "$BIN/rapp-keyring" version >/dev/null 2>&1; then
  die "the installed binary does not run"
fi
say "self-check passed: $("$BIN/rapp-keyring" version)"

# ---- guidance --------------------------------------------------------------

printf '\n'
case ":$PATH:" in
  *":$BIN:"*) ;;
  *)
    printf 'Add %s to your PATH:\n\n' "$BIN"
    printf '  echo '"'"'export PATH="%s:$PATH"'"'"' >> ~/.zshrc && exec zsh\n\n' "$BIN"
    ;;
esac

printf 'Next:\n\n'
printf '  rapp-keyring init\n'
printf '  rapp-keyring scan                      # find plaintext secrets you already have\n'
printf "  printf '%%s' \"\$KEY\" | rapp-keyring set azure/storage-key --stdin\n"
printf '  rapp-keyring run --grant azure/storage-key -- ./deploy.sh\n\n'
printf 'Docs: https://github.com/%s\n\n' "$REPO"
