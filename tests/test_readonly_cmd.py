#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks"))
from readonly_cmd import is_read_only

ALLOW = [
    # the command that started this whole thing
    'for d in */; do n=${d%/}; g=$( [ -d "$n/.git" ] && echo git || echo "-" ); '
    'sz=$(du -sh "$n" 2>/dev/null | cut -f1); echo "$n | $g | $sz"; done',
    "ls -la",
    "ls",
    "grep -rn 'foo' .",
    "echo $(ls | wc -l)",
    'echo "count: $(ls | wc -l)"',
    "echo $(dirname $(pwd))",
    "cd src && ls",
    "du -sh x 2>/dev/null",
    "git log --oneline | head -20",
    "( cd x && ls )",
    "LC_ALL=C sort file",
    "find . -name '*.md'",
    "find . -type f -name '*.py' | head",
    "cat a.txt b.txt | sort | uniq -c | sort -rn | head -10",
    "sed -n '1,20p' file.txt",
    "awk '{print $1}' file.txt",
    "timeout 30 grep -r foo .",
    "env",
    "env FOO=bar ls",
    "while read -r l; do echo x; done" if False else "ls | wc -l",
    "git status --short",
    "git config --get user.email",
    "ls > /dev/null",
    "ls 2>&1 | head",
    "stat -c '%s' file",
    "if [ -d .git ]; then echo yes; else echo no; fi",
    "test -f x && cat x",
    "printf '%s\\n' a b c",
    "tree -L 2",
    "wc -l $(git ls-files)",
    "grep '|' file",
    'grep "a > b" file',
    "echo 'a && b'",
    # arg-checked commands, safe forms
    "sed -n '1,20p' file",
    "sed -n '5p' file",
    "sed 's/foo/bar/g' file",
    "sed -n '/pat/p' file",
    "awk -F: '{print $1}' /etc/passwd",
    "awk '{n++} END {print n}' f",
    "uniq -c file",
    "uniq file",
    "tree -L 3 -a",
    "fd -e py",
    "git -C /srv/project status",
    "git log -n 5 --format=%H",
    "find . -printf '%p\\n'",
    "find . -newer f -print",
    "cat f | uniq",
    "ls -la\ngrep foo bar",
    "git branch",
    "git branch -a",
    "git branch -vv",
    "git remote -v",
    "git remote show origin",
    "git reflog show",
    "git config --list",
    "git status\ngit log\nls",
    "ls\n\n  \n grep x y",
]

DENY = [
    "rm -rf /tmp/x",
    "ls > out.txt",
    "ls >> out.txt",
    "cat <<EOF\nhi\nEOF",
    "echo `date`",
    "$CMD arg",
    'eval "$x"',
    "python3 -c 'print(1)'",
    "ls | xargs rm",
    "find . -delete",
    "find . -exec rm {} \\;",
    "awk 'BEGIN{system(\"rm x\")}'",
    "sed -i s/a/b/ file",
    "sort -o f f",
    "./scripts/check.sh",
    "npm install",
    "curl http://example.com",
    "git push",
    "git commit -m x",
    "git checkout main",
    "cat f > g",
    "tee out.txt",
    "mv a b",
    "chmod +x f",
    "bash script.sh",
    "diff <(ls) <(ls)",
    "echo hi > /tmp/x",
    "ls; rm -rf /tmp/y",
    "ls && rm x",
    "echo $(rm -rf /tmp/z)",
    'echo "$(rm -rf /tmp/z)"',
    "git config user.email me@x.com",
    "sort --output=f f",
    "awk '{print > \"out\"}' f",
    "source ~/.bashrc",
    "kill -9 1",
    # holes found during the allowlist re-audit
    "awk '{print $1 > \"/tmp/x\"}' f",
    "awk '{print | \"sh\"}' f",
    "awk 'BEGIN{while((getline l < \"/etc/passwd\")>0) print l}'",
    "fd -x rm {}",
    "fd --exec rm",
    "tree -o out.txt",
    "uniq in.txt out.txt",
    "sed 's/a/b/w /tmp/out' f",
    "sed -n 'w /tmp/out' f",
    "sed 's/a/b/e' f",
    "sed -f script.sed f",
    "sed -i.bak s/a/b/ f",
    "git tag v1",
    "git config user.name x",
    "command rm -rf /tmp/x",
    "timeout 5 rm -rf /tmp/x",
    "env FOO=1 rm x",
    "nice -n 10 npm install",
    "/usr/bin/rm x",
    "/opt/evil.sh",
    # git tightening
    "git branch -d feature",
    "git branch newbranch",
    "git remote add origin url",
    "git remote remove origin",
    "git reflog delete HEAD@{0}",
    "git diff --output=/tmp/x",
    "git -c core.pager='rm -rf /tmp/x' log",
    "git grep -O 'rm -rf' pat",
    # newline as a command separator (regression: was swallowed as whitespace)
    "ls\nrm -rf /tmp/x",
    "ls\r\nrm x",
    "cat a\nsed -i s/x/y/ b",
    "ls #\nrm x",
]

fails = 0
for c in ALLOW:
    if not is_read_only(c):
        print("FAIL (expected ALLOW): %r" % c)
        fails += 1
for c in DENY:
    if is_read_only(c):
        print("FAIL (expected DENY):  %r" % c)
        fails += 1

print("core: %d/%d passed" % (len(ALLOW) + len(DENY) - fails, len(ALLOW) + len(DENY)))

# --- appended: holes closed after extracting Claude Code's own read-only sets
EXTRA = [
    ("jq -f prog.jq data.json", False),
    ("jq --rawfile x /etc/passwd . f", False),
    ("jq -L /tmp '.' f", False),
    ("jq '$ENV.HOME' f", False),
    ("find . -files0-from list", False),
    ("cd repo && git status", False),
    ("cd a && cd b && ls", False),
    ("pushd x && git log", False),
    ("jq '.name' package.json", True),
    ("jq -r '.a.b' f", True),
    ("cd src && ls -la", True),
    ("git status && ls", True),
    ("strings binary | head", True),
    ("hexdump -C f | head", True),
    ("od -c f", True),
    ("tr a-z A-Z < f", True),
    ("cmp a b", True),
    ("nproc", True),
]
extra_fail = 0
for _cmd, _want in EXTRA:
    if is_read_only(_cmd) != _want:
        print("FAIL (extra, want %s): %r" % (_want, _cmd))
        extra_fail += 1
print("extra: %d/%d passed" % (len(EXTRA) - extra_fail, len(EXTRA)))

# --- appended: holes found by cross-checking GTFOBins + Codex CLI + the
# --- documented Claude Code read-only rules (peer research pass)
HARDENING = [
    ("PAGER='sh -c \"exec sh\"' git log", False),
    ("GIT_EXTERNAL_DIFF=evil git diff", False),
    ("LD_PRELOAD=/tmp/x.so ls", False),
    ("BASH_ENV=/tmp/x sh -c ls", False),
    ("PATH=/tmp ls", False),
    ("LESSOPEN='|sh %s' cat f", False),
    ("IFS=x ls", False),
    ("LC_ALL=C sort file", True),
    ("LANG=C grep foo f", True),
    ("TZ=UTC date", True),
    ("n=${d%/}; echo x", True),
    ("x=1; y=2; echo $x", True),
    ("find . *", False),
    ("sort *", False),
    ("git log *", False),
    ("sed -n '1,5p' *", False),
    ("rg foo *", False),
    ("find . -name '*.py'", True),
    ("ls *.ts", True),
    ("wc -l src/*.py", True),
    ("cat *.md", True),
    ("rg --pre /tmp/evil foo", False),
    ("rg -z foo", False),
    ("rg --search-zip foo", False),
    ("file -m /tmp/magic x", False),
    ("file --files-from list", False),
    ("rg -n foo src", True),
    ("file x.bin", True),
    ("ionice ls", False),
    ("watch ls", False),
    ("setsid ls", False),
    ("flock /tmp/l ls", False),
    ("nohup ls", False),
    ("timeout 5 ls", True),
    ("nice ls", True),
    ("env /bin/sh", False),
    ("timeout 0 /bin/sh", False),
    ("nice /bin/sh", False),
    ("stdbuf -i0 /bin/sh", False),
]
hard_fail = 0
for _cmd, _want in HARDENING:
    if is_read_only(_cmd) != _want:
        print("FAIL (hardening, want %s): %r" % (_want, _cmd))
        hard_fail += 1
print("hardening: %d/%d passed" % (len(HARDENING) - hard_fail, len(HARDENING)))

# --- appended: `gh` is a raw GitHub API client, so it is gated to GET/HEAD
# --- plus a read-only subcommand set. Repo research works; writes prompt.
GH = [
    ("gh api repos/uwonu606/claude-plan-mode-autoallow", True),
    ("gh api users/uwonu606 --jq '.id'", True),
    ("gh api repos/cli/cli/releases --paginate", True),
    ("gh api /repos/{owner}/{repo}/pulls", True),
    ("gh api search/repositories -X GET -f q=hooks", True),
    ("gh api repos/x/y -H 'Accept: application/vnd.github+json'", True),
    ("gh api rate_limit --method GET", True),
    ("gh repo view cli/cli", True),
    ("gh repo list uwonu606", True),
    ("gh pr list --state open", True),
    ("gh pr diff 42", True),
    ("gh issue view 7", True),
    ("gh run list --limit 5", True),
    ("gh release view v1.0", True),
    ("gh search repos claude hooks", True),
    ("gh auth status", True),
    ("gh api repos/x/y | jq '.stargazers_count'", True),
    ("for r in a b; do gh api repos/uwonu606/$r --jq .name; done", True),
    ("gh api -X DELETE repos/uwonu606/test", False),
    ("gh api --method DELETE repos/x/y", False),
    ("gh api -X PATCH repos/x/y -f name=z", False),
    ("gh api repos/x/y/issues -f title=hi", False),
    ("gh api repos/x/y/issues -F title=@body.txt", False),
    ("gh api --method=POST repos/x/y/forks", False),
    ("gh api graphql -f query='mutation{...}'", False),
    ("gh api graphql", False),
    ("gh api user/keys --input key.json", False),
    ("gh repo create newrepo --public", False),
    ("gh repo delete x", False),
    ("gh repo clone x", False),
    ("gh pr merge 42", False),
    ("gh pr create --title x", False),
    ("gh release create v1", False),
    ("gh run download 123", False),
    ("gh secret set TOKEN", False),
    ("gh gist create f.txt", False),
    ("gh auth token", False),
    ("gh api repos/x/y && gh api -X DELETE repos/x/y", False),
]
gh_fail = 0
for _cmd, _want in GH:
    if is_read_only(_cmd) != _want:
        print("FAIL (gh, want %s): %r" % (_want, _cmd))
        gh_fail += 1
print("gh: %d/%d passed" % (len(GH) - gh_fail, len(GH)))

# ------------------------------------------------------------------ log

import io
import json as _json
import tempfile

import readonly_cmd


def run_main(command, cwd=None):
    """Drive main() the way the hook does and return what it printed."""
    payload = {"permission_mode": "plan", "tool_name": "Bash",
               "tool_input": {"command": command}}
    if cwd:
        payload["cwd"] = cwd
    stdin, stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(_json.dumps(payload)), io.StringIO()
    try:
        readonly_cmd.main()
        return sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = stdin, stdout


def read_log(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rows.append(_json.loads(line))
            except ValueError:
                continue
    return rows


log_checks = []


def log_check(name, ok):
    log_checks.append((name, bool(ok)))


_saved_env = os.environ.get("PLAN_MODE_AUTOALLOW_LOG")
_saved_dir = os.environ.get("CLAUDE_CONFIG_DIR")
_tmp = tempfile.mkdtemp(prefix="autoallow-log-")
try:
    logfile = os.path.join(_tmp, "denied.jsonl")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile

    out = run_main("rm -rf /tmp/x", cwd="/srv/project")
    rows = read_log(logfile)
    log_check("denial is logged", len(rows) == 1)
    log_check("denial logs the command",
              rows and rows[0].get("command") == "rm -rf /tmp/x")
    log_check("denial logs a reason", rows and rows[0].get("reason"))
    log_check("denial logs a rule", rows and rows[0].get("rule"))
    log_check("denial logs the detail separately",
              rows and rows[0].get("detail") == "rm")
    log_check("rule holds no variable part",
              rows and "rm" not in rows[0].get("rule", "rm"))
    log_check("denial logs cwd", rows and rows[0].get("cwd") == "/srv/project")
    log_check("denial prints no decision", out == "")
    log_check("log file is not world-readable",
              (os.stat(logfile).st_mode & 0o077) == 0)

    out = run_main("ls -la")
    log_check("allowed command prints allow", '"allow"' in out)
    log_check("allowed command is not logged", len(read_log(logfile)) == 1)

    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = "off"
    run_main("rm -rf /tmp/y")
    log_check("logging honours off switch", len(read_log(logfile)) == 1)
    log_check("off switch reported by log_path", readonly_cmd.log_path() is None)

    # Rotation keeps the recent entries and moves the old file aside.
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile
    with open(logfile, "w", encoding="utf-8") as fh:
        fh.write("x" * (readonly_cmd.LOG_MAX_BYTES + 1))
    run_main("sed -i s/a/b/ f")
    log_check("oversized log rotates", os.path.exists(logfile + ".1"))
    log_check("rotated log restarts", len(read_log(logfile)) == 1)

    # A log that cannot be written must not change the decision or raise.
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(_tmp, "nope", "d.jsonl")
    log_check("unwritable log stays silent on deny", run_main("rm -rf /tmp/z") == "")
    log_check("unwritable log still allows", '"allow"' in run_main("ls"))

    # explain() is what makes the log triageable.
    log_check("explain returns None when allowed",
              readonly_cmd.explain("ls -la") is None)
    log_check("explain names the sed rule",
              "sed" in (readonly_cmd.explain("sed -i s/a/b/ f") or {})
              .get("reason", "").lower())
    log_check("explain names the cd/git rule",
              "cd" in (readonly_cmd.explain("cd /x && git log") or {})
              .get("reason", "").lower())

    # The point of splitting rule from detail: two rejections that differ only
    # in the value must land in the same bucket.
    a = readonly_cmd.explain("echo x > a.txt")
    b = readonly_cmd.explain("echo y > b.txt")
    log_check("same rule for different targets", a["rule"] == b["rule"])
    log_check("details differ", a["detail"] != b["detail"])
    log_check("reasons still differ", a["reason"] != b["reason"])
    log_check("multi-argument rule keeps both values",
              readonly_cmd.explain("gh pr merge 1")["detail"] == "pr merge")

    # --report must survive a malformed line and must include the rotated file.
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile
    with open(logfile, "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    with open(logfile + ".1", "w", encoding="utf-8") as fh:
        fh.write(_json.dumps({"ts": "2026-01-01T00:00:00+0900",
                              "rule": "older rule", "detail": "x",
                              "reason": "older rule x",
                              "command": "old cmd"}) + "\n")
    log_check("load_log reads the rotated file too",
              len(readonly_cmd.load_log(logfile)) > len(read_log(logfile)))
    log_check("rotated entries come first",
              readonly_cmd.load_log(logfile)[0].get("rule") == "older rule")
    stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        rc = readonly_cmd.report()
        text = sys.stdout.getvalue()
    finally:
        sys.stdout = stdout
    log_check("report succeeds", rc == 0)
    log_check("report groups by rule", "denials" in text and "rules" in text)

    # Default location: its own directory, not loose in the config root.
    os.environ.pop("PLAN_MODE_AUTOALLOW_LOG", None)
    os.environ["CLAUDE_CONFIG_DIR"] = _tmp
    default = readonly_cmd.log_path()
    log_check("default log sits in its own directory",
              default == os.path.join(_tmp, "plan-mode-autoallow",
                                      "denied.jsonl"))
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(
        _tmp, "made", "up", "denied.jsonl")
    run_main("rm -rf /tmp/w")
    log_check("missing parent directories are created",
              os.path.exists(os.path.join(_tmp, "made", "up", "denied.jsonl")))
finally:
    if _saved_env is None:
        os.environ.pop("PLAN_MODE_AUTOALLOW_LOG", None)
    else:
        os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _saved_env
    if _saved_dir is None:
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
    else:
        os.environ["CLAUDE_CONFIG_DIR"] = _saved_dir
    import shutil
    shutil.rmtree(_tmp, ignore_errors=True)

log_fail = 0
for _name, _ok in log_checks:
    if not _ok:
        print("FAIL (log): %s" % _name)
        log_fail += 1
print("log: %d/%d passed" % (len(log_checks) - log_fail, len(log_checks)))

total = (len(ALLOW) + len(DENY) + len(EXTRA) + len(HARDENING) + len(GH)
         + len(log_checks))
total_fail = fails + extra_fail + hard_fail + gh_fail + log_fail
print("TOTAL: %d/%d passed" % (total - total_fail, total))
sys.exit(1 if total_fail else 0)
