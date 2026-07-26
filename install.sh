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

# The denial log gets its own directory, and the directory gets a README. The
# log is the one file here a stranger runs into without context -- it appears on
# its own, months later, in a config dir they were browsing for something else.
LOGDIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plan-mode-autoallow"
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"
cat > "$LOGDIR/README.md" <<EOF
# plan-mode-autoallow — 거부 로그

이 디렉터리는 \`$DEST/plan-mode-autoallow.sh\` 훅이 쓴다. Claude Code가 plan
mode일 때 실행하려던 Bash 명령 중 **읽기 전용으로 판정되지 않아 권한 프롬프트로
넘어간 것**이 여기 쌓인다. 통과한 명령은 기록하지 않는다.

- \`denied.jsonl\` — 한 줄에 한 건, JSON Lines
- \`denied.jsonl.1\` — 2 MB를 넘으면 밀려난 이전 파일

레코드:

| 필드 | 뜻 |
|---|---|
| \`ts\` | 시각 (ISO 8601) |
| \`rule\` | 걸린 규칙. **값이 들어가지 않는 고정 문자열이라 집계 키로 쓴다** |
| \`detail\` | 그 규칙을 건드린 값 (\`docker\`, \`-i\`, \`a.txt\` …) |
| \`reason\` | \`rule\`과 \`detail\`을 합친 사람이 읽는 문장 |
| \`command\` | 명령줄 전체 |
| \`cwd\` | 실행하려던 디렉터리 |

집계해서 보려면 (규칙별 건수 + 규칙 안에서 값별 건수):

\`\`\`sh
python3 $DEST/readonly_cmd.py --report
\`\`\`

\`command not on read-only allowlist\`가 상위에 있고 \`detail\`에 같은 명령이
반복되면, 그 명령을 allowlist에 넣을지 검토할 때다. 규칙과 allowlist는
\`$DEST/readonly_cmd.py\`에 있다.

끄려면 환경변수 \`PLAN_MODE_AUTOALLOW_LOG=off\`. 다른 경로로 보내려면 같은
변수에 파일 경로를 준다.

명령줄 전체가 그대로 들어가므로 셸 히스토리와 같은 수준으로 다룰 것.
이 파일은 \`install.sh\`가 매번 다시 쓴다.
EOF

echo "installed to $DEST"
echo "denial log directory: $LOGDIR"
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
