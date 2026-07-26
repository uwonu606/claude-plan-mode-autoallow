#!/usr/bin/env bash
# PreToolUse hook: auto-allow tool calls while Claude Code is in plan mode,
# except AskUserQuestion and ExitPlanMode, which must still prompt the user.
#
# Bash is the one tool that still needs its argument inspected -- plan mode
# blocks Edit/Write but not `rm` -- so it is handed to readonly_cmd.py, which
# allows the call only when every command in the line is read-only.
#
# The bash part stays free of subprocesses so the common paths (any non-plan
# mode, any non-Bash tool) cost only the shell spawn. python3 is started only
# for Bash calls made while in plan mode.

IFS= read -r -d '' input

# Strip all spaces so both compact and pretty-printed JSON match the same
# literal patterns below (bash builtin, no subprocess).
compact=${input// /}

# Not in plan mode: do nothing, fall through to normal permission flow.
[[ $compact == *'"permission_mode":"plan"'* ]] || exit 0

# Let these keep their native prompts even in plan mode.
if [[ $compact == *'"tool_name":"AskUserQuestion"'* || $compact == *'"tool_name":"ExitPlanMode"'* ]]; then
  exit 0
fi

# Bash: allow only if the command line parses as read-only. The parser prints
# the allow decision itself, or nothing. Exit here either way -- falling
# through would blanket-allow the very commands the parser just rejected.
if [[ $compact == *'"tool_name":"Bash"'* ]]; then
  # Parameter expansion, not `dirname`: no subprocess on this path.
  hook_dir=${BASH_SOURCE[0]%/*}
  # -S skips site initialization. Importing the parser rather than running it
  # as a script lets Python reuse the cached .pyc instead of recompiling on
  # every call: 22ms -> 18ms measured. The cache regenerates itself when the
  # source changes, so there is nothing to invalidate by hand.
  printf '%s' "$input" | python3 -S -c 'import sys
sys.path.insert(0, sys.argv[1])
import readonly_cmd
readonly_cmd.main()' "$hook_dir"
  exit 0
fi

printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"plan mode: auto-allow"}}'
