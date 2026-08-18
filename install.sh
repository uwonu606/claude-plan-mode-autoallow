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

# The judgment log gets its own directory, and the directory gets a README. The
# log is the one file here a stranger runs into without context -- it appears on
# its own, months later, in a config dir they were browsing for something else.
LOGDIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plan-mode-autoallow"
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"
cat > "$LOGDIR/README.md" <<EOF
# plan-mode-autoallow — 판정 로그

이 디렉터리는 \`$DEST/plan-mode-autoallow.sh\` 훅이 쓴다. Claude Code가 plan
mode일 때 실행하려던 Bash 명령의 판정 기록이다. 자동 허용된 명령은 기록하지
않는다.

- \`judgments.jsonl\` — 판정 한 줄씩. append-only이고 **로테이션이 없다**
- \`bodies/<ref>\` — 명령 본문. 부피와 민감도가 여기 모이고, 상한도 여기에만
  걸린다 (2 MB를 넘으면 오래된 본문부터 지운다)
- \`denied.jsonl.0\` / \`allowed.jsonl.0\` — \`--migrate\`가 접어 넣고 옆으로
  치워둔 옛 로그. 지워도 된다

파일을 판정 축(허용/거부)으로 가르지 않는다. 그건 훅이 이미 아는 축이고,
읽을 때 필요한 구분 — 파서가 **쓰기임을 입증한 것**과 **모른다고 자백한 것** —
은 저장이 아니라 재생으로 계산한다. 규칙 하나를 승격하면 관련 줄이 저절로
목록에서 빠진다.

\`judgments.jsonl\` 한 줄:

| 필드 | 뜻 |
|---|---|
| \`ts\` | 시각 (ISO 8601) |
| \`rule\` | 걸린 규칙. **값이 들어가지 않는 고정 문자열이라 집계 키로 쓴다** |
| \`detail\` | 그 규칙을 건드린 값 (\`docker\`, \`-i\`, \`a.txt\` …) |
| \`cwd\` | 실행하려던 디렉터리 (있을 때만) |
| \`head\` | 본문 첫 줄 앞 160자. \`tail\`로 훑을 때 읽을 것 |
| \`ref\` | \`bodies/\` 안의 본문 파일 이름 |
| \`bytes\` | 본문 길이 |

\`rule\`이 \`allowed by classifier\`인 줄은 LLM 계층
(\`PLAN_MODE_AUTOALLOW_LLM=on\`)이 읽기 전용이라 판정한 것이다. 캐시이자 승격
후보이고, 캐시 적중은 본문으로 확인하므로 본문이 정리되면 다음에 다시 묻는다.

보는 방법은 둘이다:

\`\`\`sh
python3 $DEST/readonly_cmd.py --report   # 규칙별 집계 + 승격 후보
python3 $DEST/readonly_cmd.py --open     # 미해결 명령만
\`\`\`

\`--open\`은 파서가 모른다고 자백한 것만 골라 보여준다. 거기 같은 명령어가
반복되면 파서에 넣을지 검토할 때다. 규칙과 allowlist는
\`$DEST/readonly_cmd.py\`에 있다.

끄려면 환경변수 \`PLAN_MODE_AUTOALLOW_LOG=off\`. 다른 경로로 보내려면 같은
변수에 파일 경로를 준다.

명령줄 전체가 \`bodies/\`에 그대로 모이므로 셸 히스토리와 같은 수준으로 다룰 것.
이 파일은 \`install.sh\`가 매번 다시 쓴다.
EOF

echo "installed to $DEST"
echo "judgment log directory: $LOGDIR"
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
echo
echo "Optional: PLAN_MODE_AUTOALLOW_LLM=on refers commands the parser does not"
echo "recognise to 'claude -p' for a second opinion. Off by default because it"
echo "spends tokens; see the \"모르는 명령\" section of the project README."
