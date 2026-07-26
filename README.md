# claude-plan-mode-autoallow

A Claude Code `PreToolUse` hook that stops permission prompts from interrupting **plan mode**, while still prompting for anything that can write, delete, or execute.

In plan mode the agent is supposed to be reading and thinking, not changing your machine. But every `ls`, `grep`, or `find` it runs can raise a permission prompt, and each prompt breaks the flow of the very activity plan mode exists for. This hook auto-approves the read-only work and leaves the two prompts you actually want: `AskUserQuestion` and the final plan approval (`ExitPlanMode`).

Everything outside plan mode is untouched.

## Why a hook, and not `permissions.allow`

Two reasons, both discovered the hard way.

**Prefix rules cannot express shell one-liners.** `Bash(...)` allow rules match against a "command prefix" that Claude Code extracts from the command. When the command contains a command substitution, that extraction returns `command_injection_detected` and no prefix at all, so *no* allow rule can match. And even when extraction succeeds, a line starting with `for` has `for` as its prefix. This real command is read-only and could not be allowed by any rule:

```bash
for d in */; do n=${d%/}; g=$( [ -d "$n/.git" ] && echo git || echo "-" ); \
  sz=$(du -sh "$n" 2>/dev/null | cut -f1); echo "$n | $g | $sz"; done
```

**The sandbox is off-limits here.** Claude Code can auto-approve sandboxed Bash (`sandbox.autoAllowBashIfSandboxed`), but both entry points to that path bail out when the mode is `plan`. Rules and hooks are the only mechanisms left, and rules are ruled out above.

## Why not just turn on auto mode

Auto mode's permission classifier is a two-stage **LLM call** that takes the conversation transcript as input. It costs a network round trip per decision, spends tokens, degrades as the transcript grows (`Classifier transcript exceeded context window → falling back to manual approval`), and fails closed when the API is unavailable. This hook decides in ~20 ms with no network and no tokens.

Note that the half of auto mode that *is* free — Claude Code's built-in `isReadOnly` check — already runs in plan mode. This hook is not a replacement for it; it covers the compound commands that check rejects.

## What it allows

A command is allowed only if **every** command in the line passes. The line is tokenized quote-aware, `$(...)` is validated recursively, and the line is split on `; && || | & newline ( )`.

Allowed: a fixed list of read-only tools (`ls cat head tail wc grep rg stat du df diff cut tr strings hexdump od …`), plus these with their arguments checked:

| Command | Rejected when |
|---|---|
| `find` | `-exec` `-execdir` `-ok` `-okdir` `-delete` `-fprint*` `-fls` `-files0-from` |
| `sort` | `-o` / `--output` |
| `awk` | `system` `close(` `ENVIRON` `getline` any `>` redirection or `\|` pipe in the program |
| `sed` | anything outside a small set of print/substitute script shapes (`w FILE` and `e` are write/exec) |
| `git` | any subcommand outside a read-only set; `-c` (can set `core.pager` to a shell command); `--output`; mutating `branch`/`remote`/`reflog` actions |
| `jq` | `-f` `--rawfile` `--slurpfile` `-L` `--run-tests`; `$ENV` / `include` / `import` in the program |
| `rg` | `--pre` `--pre-glob` `--hostname-bin` `-z` `--search-zip` |
| `file` | `-m` `--magic-file` `-f` `--files-from` |
| `fd` | `-x` `-X` `--exec` `--exec-batch` |
| `tree` | `-o` |
| `uniq` | a second operand (it is an output file) |
| `gh` | any method but `GET`/`HEAD`; request fields (`-f`/`-F`, which switch gh to POST) unless the method is explicitly GET; `--input`; `graphql`; any subcommand outside a read-only set |

`gh` deserves a note. `gh api` is a raw authenticated client for the entire GitHub API, so what it can do equals the token's scopes — with a typical `repo, workflow, gist, admin:public_key` token that includes rewriting history, writing `.github/workflows/*.yml` (arbitrary code execution on runners with your secrets), and adding SSH keys to the account. A prefix rule like `Bash(gh api *)` cannot express "GET only", which is exactly why this belongs in a parser. Repo research (`gh api repos/...`, `gh repo view`, `gh pr list`) passes; `gh api -X DELETE`, `gh repo create`, `gh pr merge`, `gh secret set` prompt.

Rejected outright: output redirection to anything but `/dev/null`-style targets, heredocs, process substitution, backticks, indirect execution (`$CMD`, `eval`), interpreters (`python3 -c`, `bash script.sh`), `xargs`, and any command not on the list.

Two whole-line rules mirror checks Claude Code makes itself:

- **`cd` then `git`** is rejected — git can execute hooks and fsmonitor from the target directory.
- **More than one `cd`** is rejected — the effective working directory becomes hard to reason about.

`VAR=value cmd` prefixes are restricted to locale/formatting variables. Without this, `PAGER='sh -c "exec sh"' git log` is a shell escape. Assignment-only segments (`n=${d%/}`) are unrestricted, since they set a shell variable and run nothing.

Unquoted globs next to `find` / `sort` / `sed` / `git` / `rg` are rejected: the glob can expand to a filename like `-delete`. Quoted globs and globs next to safe commands (`ls *.ts`, `cat *.md`) are fine.

## Threat model

This is a **guardrail against the agent accidentally running something destructive while planning** — not a defense against a determined attacker. It is static string analysis; enough obfuscation will get past it. If you need an actual boundary, you want a sandbox or a VM, not a hook.

Design bias: default deny. Anything unparseable, unknown, or ambiguous falls through to the normal prompt. A false negative costs you one prompt; a false positive runs a command you did not approve.

## Install

Requires `bash` and `python3` (standard library only). No `jq`.

```sh
git clone https://github.com/uwonu606/claude-plan-mode-autoallow
cd claude-plan-mode-autoallow
./install.sh
```

`install.sh` copies the two files in `hooks/` to `~/.claude/hooks/` and prints the settings snippet to add. Or do it by hand — copy `hooks/` anywhere and register it in `~/.claude/settings.json`:

```json
{
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
}
```

`settings.example.json` also contains a `permissions.allow` / `permissions.deny` block worth reading: the allow entries cut prompts in *normal* mode too, and the deny entries keep credential files unreadable.

## Cost

Measured on WSL2, 50 iterations each:

| Path | Per call |
|---|---|
| Any non-plan mode | 1.1 ms |
| Plan mode, non-Bash tool | 1.1 ms |
| Plan mode, Bash | ~20 ms |

The bash half spawns no subprocesses; `python3` starts only for Bash calls made in plan mode.

## Tests

```sh
python3 tests/test_readonly_cmd.py
```

222 cases covering the allow set, the escape techniques above, and regressions. Two bugs found by this suite, both of which wrongly *allowed* commands:

- `printf ... | exec python3 ...` — `exec` inside a pipeline replaces the subshell, not the script, so the script continued to the blanket-allow line and approved `rm -rf`.
- The tokenizer checked `isspace()` before operator matching, so a newline was swallowed as whitespace and `ls\nrm -rf /tmp/x` parsed as `ls` with `rm` as an argument.

If you extend the allowlist, add cases in both directions.

## Provenance

The allowlist was cross-checked against three sources rather than written from intuition: Claude Code's own read-only sets (extracted from the 2.1.220 binary), [OpenAI Codex CLI's `is_safe_command.rs`](https://github.com/openai/codex/blob/main/codex-rs/shell-command/src/command_safety/is_safe_command.rs), and [GTFOBins](https://gtfobins.github.io/) used in reverse — as a list of commands that look harmless but can write files or spawn shells. Most of the argument checks above came from that comparison, not from the original design.

## License

MIT
