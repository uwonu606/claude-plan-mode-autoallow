#!/usr/bin/env bash
# Copy the hook into ~/.claude/hooks and print the settings snippet to add.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hooks"
DEST="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/hooks"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

mkdir -p "$DEST"
for f in plan-mode-autoallow.sh readonly_cmd.py; do
  if [ -e "$DEST/$f" ] && ! cmp -s "$SRC/$f" "$DEST/$f"; then
    cp "$DEST/$f" "$DEST/$f.bak.$(date +%Y%m%d%H%M%S)"
    echo "backed up existing $f"
  fi
  cp "$SRC/$f" "$DEST/$f"
done
chmod +x "$DEST/plan-mode-autoallow.sh"

echo "installed to $DEST"
echo
echo "Add this to ${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json (merge with"
echo "any existing \"hooks\" key -- do not overwrite the whole file):"
cat <<'JSON'

  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "bash \"$HOME/.claude/hooks/plan-mode-autoallow.sh\"" }
        ]
      }
    ]
  }

JSON
echo "Then start a new Claude Code session -- hooks load at startup."
