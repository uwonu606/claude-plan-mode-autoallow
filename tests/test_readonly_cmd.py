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
    "env LANG=C ls",
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
    "curl http://example.com",
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
    # `env` in front must not launder any of the above. It used to: the wrapper
    # discarded assignments instead of checking them, so every vector on this
    # list came back to life with four characters in front of it.
    ("env PAGER='sh -c \"exec sh\"' git log", False),
    ("env GIT_EXTERNAL_DIFF=/usr/bin/id git diff", False),
    ("env GIT_SSH_COMMAND=id git ls-remote origin", False),
    ("env GIT_PAGER=sh git log", False),
    ("env LD_PRELOAD=/tmp/x.so ls", False),
    ("env BASH_ENV=/tmp/x ls", False),
    ("env FOO=bar ls", False),
    # -S splits its operand into a command line, so the wrapped command never
    # appears as a word of its own. Attached form only -- `env -S "sh -c id"`
    # separates into a word that was already rejected as an unknown command.
    ('env -S"touch pwned"', False),
    ('env -S"sh -c id"', False),
    ('env -vS"id"', False),
    ('env --split-string="touch x"', False),
    # -a renames argv[0], so the validated name is not the one that runs.
    ("env -a foo /bin/sh", False),
    ("env -C /tmp ls", False),
    ("env -i ls", True),
    ("env - ls", True),
    ("env -u PATH ls", True),
    ("env -uPATH ls", True),
    ("env --unset=PATH ls", True),
    ("env LANG=C ls", True),
    ("env LC_ALL=C sort file", True),
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
    # file, sort and awk list the flags they accept instead of the ones they
    # refuse. Each was moved after a denylist let something through, so the
    # cases below are the specific escapes plus enough ordinary usage to catch
    # an allowlist that is too narrow. Short flags bundle and carry attached
    # values, which is where the first attempt at this broke.
    ("file -C", False),
    ("file --compile", False),
    ("file -S x", False),
    ("file -z x", False),
    ("file --magic-file=/tmp/m x", False),
    ("file -b f", True),
    ("file -bi f", True),
    ("file --mime-type f", True),
    ("file -e soft x", True),
    ("file -P bytes=100 f", True),
    ("sort --compress-program=sh f", False),
    ("sort --compress-program sh f", False),
    ("sort -oout f", False),
    ("sort --output=out f", False),
    ("sort -rn f", True),
    ("sort -k2,3 -t: f", True),
    ("sort -S 50% --parallel=4 f", True),
    ("sort --files0-from=l", True),
    ("awk -f prog.awk f", False),
    ("awk --file=prog.awk f", False),
    ("awk -o out.awk 'BEGIN{}'", False),
    ("awk -p prof 'BEGIN{}'", False),
    ("awk -d vars 'BEGIN{}'", False),
    ("awk -l lib 'BEGIN{}'", False),
    ("awk --load=lib 'BEGIN{}'", False),
    ("awk -E prog.awk", False),
    ("awk -e '{system(\"id\")}' f", False),
    ("awk --source='{print|\"sh\"}' f", False),
    ("awk -F: '{print $1}' f", True),
    ("awk -F : '{print $1}' f", True),
    ("awk -v x=1 '{print x}' f", True),
    ("awk -e '{print $1}' f", True),
    ("awk '{ if (a >= b) print }' f", True),
    # date prints through a +FORMAT operand and nothing else, so any other
    # operand is BSD's flagless way of setting the clock. -s covers only GNU.
    ("date -s 2020-01-01", False),
    ("date --set=2020-01-01", False),
    ("date 010100002026", False),
    ("date 1231235959", False),
    ("date", True),
    ("date +%Y-%m-%d", True),
    ("date -u +%s", True),
    ("date -d yesterday +%F", True),
    ("date --date='2 days ago' +%F", True),
    ("date -Iseconds", True),
    ("date --iso-8601=seconds", True),
    # hostname renames the host from a bare operand or -F; uname -n reads it.
    ("hostname pwned", False),
    ("hostname -F /tmp/n", False),
    ("hostname", False),
    ("uname -n", True),
    # A /bin or /usr/bin prefix is only a guarantee while the path stays there.
    ("/bin/../tmp/ls", False),
    ("/usr/bin/../../tmp/ls", False),
    ("/bin/ls", True),
    ("/usr/bin/git log", True),
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

# --- appended: `javap`, `unzip` and `curl`. All three carry flags that keep
# --- working after an operand (`curl URL -o f`), so the flag walk has to scan
# --- the whole line instead of stopping at the first non-flag word.
JAVAP = [
    ("javap Foo", True),
    ("javap -c Foo", True),
    ("javap -p -c com.example.Foo", True),
    ("javap -verbose Foo", True),
    ("javap -cp build/classes Foo", True),
    ("javap -classpath /tmp/x.jar com.example.Foo | head -40", True),
    ("javap --class-path build Foo", True),
    ("javap -c -p Foo Bar", True),
    # -J hands an option straight to the JVM, which is an execution vector.
    ("javap -J-javaagent:/tmp/evil.jar Foo", False),
    ("javap Foo -J-Xmx1g", False),
    ("javap -cp", False),
    ("javap -o out Foo", False),
    ("javap --module-path", False),
]

UNZIP = [
    ("unzip -l x.zip", True),
    ("unzip -p x.zip README.md | head", True),
    ("unzip -v x.zip", True),
    ("unzip -t x.zip", True),
    ("unzip -Z x.zip", True),
    ("unzip -c x.zip f.txt", True),
    ("unzip -l x.zip -x '*.png'", True),
    ("unzip -lq x.zip", True),
    # No list flag means it extracts, quietly or not.
    ("unzip x.zip", False),
    ("unzip -q x.zip", False),
    ("unzip -o x.zip", False),
    ("unzip -d /tmp x.zip", False),
    # -d after the operand still picks the extraction directory.
    ("unzip -l x.zip -d /tmp", False),
    ("unzip -ld /tmp x.zip", False),
]

CURL = [
    ("curl https://example.com", True),
    ("curl -sSL https://example.com | head", True),
    ("curl -s https://api.github.com/rate_limit | jq .", True),
    ("curl -I https://example.com", True),
    ("curl -fsS -H 'Accept: application/json' https://x/y", True),
    ("curl --compressed --max-time 5 https://x", True),
    ("curl -o /tmp/f https://example.com", False),
    ("curl https://example.com -o /tmp/f", False),
    ("curl -O https://example.com/f.tar", False),
    ("curl --output-dir /tmp -O https://x/f", False),
    ("curl -X GET https://example.com", False),
    ("curl -X POST -d 'a=1' https://x", False),
    ("curl -T f.txt https://x", False),
    ("curl -D /tmp/h https://x", False),
    ("curl -c /tmp/jar https://x", False),
    ("curl -K /tmp/curlrc https://x", False),
    ("curl --data-binary @f https://x", False),
    ("curl -F file=@f https://x", False),
    ("curl --trace /tmp/t https://x", False),
    ("curl --etag-save /tmp/e https://x", False),
]

tool_fail = 0
for _name, _table in (("javap", JAVAP), ("unzip", UNZIP), ("curl", CURL)):
    for _cmd, _want in _table:
        if is_read_only(_cmd) != _want:
            print("FAIL (%s, want %s): %r" % (_name, _want, _cmd))
            tool_fail += 1
_tools = len(JAVAP) + len(UNZIP) + len(CURL)
print("tools: %d/%d passed" % (_tools - tool_fail, _tools))

# --- appended: `worktree list` and `merge-base` promoted to the git read set.
# --- `git -C <path>` is walked by the existing flag loop, so the promotion has
# --- to hold through it without a special case.
GITPROMOTE = [
    ("git worktree list", True),
    ("git worktree list --porcelain", True),
    ("git -C /srv/x worktree list", True),
    ("git merge-base main feature", True),
    ("git merge-base --is-ancestor a b", True),
    ("git -C /srv/x merge-base a b", True),
    ("git worktree list | wc -l", True),
    ("git worktree", False),
    ("git worktree add ../wt topic", False),
    ("git worktree remove ../wt", False),
    ("git worktree prune", False),
    ("git worktree lock ../wt", False),
    ("git worktree move ../wt ../wt2", False),
    ("git worktree repair", False),
]
promote_fail = 0
for _cmd, _want in GITPROMOTE:
    if is_read_only(_cmd) != _want:
        print("FAIL (git promote, want %s): %r" % (_want, _cmd))
        promote_fail += 1
print("git promote: %d/%d passed" % (len(GITPROMOTE) - promote_fail,
                                     len(GITPROMOTE)))

# --- appended: names the parser can settle on its own. The list was already
# --- there as the one the classifier never sees; saying so in the verdict is
# --- what takes `python3` out of the "unknown command" pile it never belonged
# --- in. Dispatchers stay unknown -- `docker` names a subject, not an act.
import readonly_cmd as rc

KNOWN_EXEC = [
    ("python3 -c 'print(1)'", "known write/exec command", "python3"),
    ("mkdir -p a/b", "known write/exec command", "mkdir"),
    ("rm -rf /tmp/x", "known write/exec command", "rm"),
    ("node script.js", "known write/exec command", "node"),
    ("ls | xargs rm", "known write/exec command", "xargs"),
    ("mkfs.ext4 /dev/sda", "known write/exec command", "mkfs.ext4"),
    ("docker ps", rc.UNKNOWN_COMMAND_RULE, "docker"),
    ("glab mr list", rc.UNKNOWN_COMMAND_RULE, "glab"),
]
known_fail = 0
for _cmd, _rule, _detail in KNOWN_EXEC:
    _v = rc.explain(_cmd)
    if not _v or _v["rule"] != _rule or _v["detail"] != _detail:
        print("FAIL (known exec, want %r/%r): %r -> %r"
              % (_rule, _detail, _cmd, _v))
        known_fail += 1
print("known exec: %d/%d passed" % (len(KNOWN_EXEC) - known_fail,
                                    len(KNOWN_EXEC)))


# --- appended: the same move one level down. `Deny("git %s", sub)` was pooling
# --- two different sentences -- "I do not know this subcommand" and "I know
# --- this one writes" -- under one rule, so `git fetch` sat in the unresolved
# --- pile forever, exactly where `python3` used to sit. Names whose write
# --- class is settled get their own verdict; names with an ordinary read form
# --- (`git tag`, `git stash list`, `git submodule status`) stay unresolved,
# --- because saying "write" there would bury a real promotion question.
KNOWN_SUB = [
    ("git fetch origin", "known write/exec git subcommand", "fetch"),
    ("git push origin main", "known write/exec git subcommand", "push"),
    ("git commit -m x", "known write/exec git subcommand", "commit"),
    ("git checkout -b b", "known write/exec git subcommand", "checkout"),
    ("git -C /srv/x fetch", "known write/exec git subcommand", "fetch"),
    ("git tag", "git", "tag"),
    ("git stash list", "git", "stash"),
    ("git submodule status", "git", "submodule"),
    ("gh auth switch", "known write/exec gh subcommand", "auth switch"),
    ("gh pr merge 3", "known write/exec gh subcommand", "pr merge"),
    ("gh repo create x", "known write/exec gh subcommand", "repo create"),
    ("gh codespace list", "gh", "codespace"),
]
sub_fail = 0
for _cmd, _rule, _detail in KNOWN_SUB:
    _v = rc.explain(_cmd)
    if not _v or _v["rule"] != _rule or _v["detail"] != _detail:
        print("FAIL (known sub, want %r/%r): %r -> %r"
              % (_rule, _detail, _cmd, _v))
        sub_fail += 1
print("known sub: %d/%d passed" % (len(KNOWN_SUB) - sub_fail, len(KNOWN_SUB)))

# The point of the split: a settled write must not be an open question.
open_checks = []
for _cmd in ("git fetch origin", "git push origin main", "gh auth switch"):
    open_checks.append(("%s is not an open question" % _cmd,
                        rc.explain(_cmd)["rule"] not in rc.OPEN_RULES))
for _cmd in ("git tag", "docker ps"):
    open_checks.append(("%s stays an open question" % _cmd,
                        rc.explain(_cmd)["rule"] in rc.OPEN_RULES))
open_fail = 0
for _label, _ok in open_checks:
    if not _ok:
        print("FAIL (open bucket): %s" % _label)
        open_fail += 1
print("open bucket: %d/%d passed" % (len(open_checks) - open_fail,
                                     len(open_checks)))

# --- appended: `cd` before `git` is no longer refused outright. The target
# --- repository is inspected instead -- local config, git verb, and the one
# --- hook a read verb can fire -- and anything that cannot be inspected is
# --- refused. The fixtures below are real repositories because that is what
# --- the check reads; a stub would test the stub.
import shutil as _shutil
import subprocess as _subprocess
import tempfile as _tempfile

cdgit_checks = []


def cdgit_check(name, ok):
    cdgit_checks.append((name, bool(ok)))


def _mkrepo(parent, name, config=(), hooks=()):
    """A real git repo, optionally polluted with config keys or hooks."""
    path = os.path.join(parent, name)
    os.makedirs(path)
    _subprocess.run(["git", "init", "-q", path], stdout=_subprocess.DEVNULL,
                    stderr=_subprocess.DEVNULL)
    for key, value in config:
        _subprocess.run(["git", "-C", path, "config", "--local", key, value],
                        stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
    for hook, mode in hooks:
        hook_path = os.path.join(path, ".git", "hooks", hook)
        with open(hook_path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(hook_path, mode)
    return path


def rule_of(command, cwd=None):
    verdict = rc.explain(command, cwd=cwd)
    return verdict and verdict["rule"]


_cdgit_tmp = _tempfile.mkdtemp(prefix="autoallow-cdgit-")
try:
    clean = _mkrepo(_cdgit_tmp, "clean")
    # Third-party keys land in sections git itself never reads, so they are not
    # a reason to refuse. Refusing them was the first draft, and it allowed 0.
    third = _mkrepo(_cdgit_tmp, "third-party", config=(
        ("vscode.x", "1"),
        ("branch.main.vscode-merge-base", "origin/main"),
        ("lfs.repositoryformatversion", "0"),
        ("remote.origin.glab-resolved-head", "main"),
    ))
    aliased = _mkrepo(_cdgit_tmp, "aliased", config=(("alias.co", "!sh"),))
    hookspath = _mkrepo(_cdgit_tmp, "hookspath",
                        config=(("core.hooksPath", "/tmp/evil"),))
    indexhook = _mkrepo(_cdgit_tmp, "index-hook",
                        hooks=(("post-index-change", 0o755),))
    inerthook = _mkrepo(_cdgit_tmp, "inert-hook",
                        hooks=(("post-index-change", 0o644),))
    otherhook = _mkrepo(_cdgit_tmp, "other-hook",
                        hooks=(("pre-commit", 0o755), ("post-checkout", 0o755)))
    plain = os.path.join(_cdgit_tmp, "not-a-repo")
    os.makedirs(plain)
    missing = os.path.join(_cdgit_tmp, "gone")

    cdgit_check("a clean repo is auto-allowed",
                is_read_only("cd %s && git status" % clean))
    cdgit_check("the rest of the line is still checked",
                is_read_only("cd %s && git log --oneline | head -20" % clean))
    cdgit_check("pushd counts the same as cd",
                is_read_only("pushd %s && git show HEAD" % clean))
    cdgit_check("git worktree list passes the inspection",
                is_read_only("cd %s && git worktree list" % clean))
    cdgit_check("third-party keys are in sections git does not read",
                is_read_only("cd %s && git status" % third))
    cdgit_check("a hook a read verb cannot fire is not a reason to refuse",
                is_read_only("cd %s && git status" % otherhook))
    cdgit_check("a post-index-change that is not executable is inert",
                is_read_only("cd %s && git status" % inerthook))

    cdgit_check("a missing target cannot be inspected",
                rule_of("cd %s && git log" % missing)
                == "cd before git: target repo unreadable")
    cdgit_check("a directory that is not a repo cannot be inspected",
                rule_of("cd %s && git log" % plain)
                == "cd before git: target repo unreadable")
    cdgit_check("an alias to a shell is not harmless",
                rule_of("cd %s && git status" % aliased)
                == "cd before git: config key is not harmless")
    cdgit_check("core.hooksPath points somewhere unchecked",
                rule_of("cd %s && git status" % hookspath)
                == "cd before git: config key is not harmless")
    cdgit_check("an executable post-index-change is the hook status fires",
                rule_of("cd %s && git status" % indexhook)
                == "cd before git: executable post-index-change hook")
    cdgit_check("ls-remote reads the remote configuration",
                rule_of("cd %s && git ls-remote" % clean)
                == "cd before git: network-touching git verb")
    cdgit_check("git remote reads the remote configuration",
                rule_of("cd %s && git remote -v" % clean)
                == "cd before git: network-touching git verb")
    cdgit_check("a variable target names no repo to inspect",
                rule_of("cd $DIR && git log") ==
                "cd before git: cd target not identifiable")
    cdgit_check("a bare cd goes home, which this parser cannot name",
                rule_of("cd && git status")
                == "cd before git: cd target not identifiable")
    cdgit_check("a glob target names no single repo",
                rule_of("cd repo* && git status", cwd=_cdgit_tmp)
                == "cd before git: cd target not identifiable")
    cdgit_check("a relative target resolves against cwd",
                rc.explain("cd clean && git status", cwd=_cdgit_tmp) is None)
    cdgit_check("a relative target without cwd is not identifiable",
                rule_of("cd clean && git status")
                == "cd before git: cd target not identifiable")
    cdgit_check("two directory changes are still refused",
                rule_of("cd %s && cd %s && git log" % (clean, third))
                == "multiple directory changes in one command")

    # Linked worktrees are where this hook's friction actually lives, and the
    # worktree config scope errors out on two conditions that are not failures:
    # the extension being off, and the file not existing yet. Reading either as
    # "unreadable" refuses every sibling worktree, which is the whole gain.
    _subprocess.run(["git", "-C", clean, "-c", "user.email=t@t", "-c",
                     "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"],
                    stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
    linked = os.path.join(_cdgit_tmp, "linked")
    _subprocess.run(["git", "-C", clean, "worktree", "add", "-q", linked,
                     "-b", "wt"],
                    stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
    cdgit_check("a linked worktree is inspectable",
                is_read_only("cd %s && git status" % linked))
    _subprocess.run(["git", "-C", clean, "config", "extensions.worktreeConfig",
                     "true"], stdout=_subprocess.DEVNULL,
                    stderr=_subprocess.DEVNULL)
    cdgit_check("the extension without the file yet is not a failed inspection",
                is_read_only("cd %s && git status" % linked))
    _subprocess.run(["git", "-C", linked, "config", "--worktree",
                     "core.hooksPath", "/tmp/evil"],
                    stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
    cdgit_check("a worktree-scoped key is read when the extension is on",
                rule_of("cd %s && git status" % linked)
                == "cd before git: config key is not harmless")
    cdgit_check("and it does not follow the main worktree",
                is_read_only("cd %s && git status" % clean))
finally:
    _shutil.rmtree(_cdgit_tmp, ignore_errors=True)

cdgit_fail = 0
for _name, _ok in cdgit_checks:
    if not _ok:
        print("FAIL (cd/git): %s" % _name)
        cdgit_fail += 1
print("cd/git: %d/%d passed" % (len(cdgit_checks) - cdgit_fail,
                                len(cdgit_checks)))

# ------------------------------------------------------------- judgment log

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


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def capture(fn, *args):
    """Run a reporter and hand back (return code, what it printed)."""
    stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = fn(*args)
        return code, sys.stdout.getvalue()
    finally:
        sys.stdout = stdout


log_checks = []


def log_check(name, ok):
    log_checks.append((name, bool(ok)))


_saved_env = os.environ.get("PLAN_MODE_AUTOALLOW_LOG")
_saved_dir = os.environ.get("CLAUDE_CONFIG_DIR")
_tmp = tempfile.mkdtemp(prefix="autoallow-log-")
try:
    logfile = os.path.join(_tmp, "judgments.jsonl")
    bodies = os.path.join(_tmp, "bodies")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile

    out = run_main("rm -rf /tmp/x", cwd="/srv/project")
    rows = read_log(logfile)
    row = rows[0] if rows else {}
    log_check("the judgment is recorded", len(rows) == 1)
    log_check("the line is the seven fields and nothing else",
              list(row) == ["ts", "rule", "detail", "cwd", "head", "ref",
                            "bytes"])
    log_check("the rule is the one the parser fired",
              row.get("rule") == "known write/exec command"
              and row.get("detail") == "rm")
    log_check("no reason field: rule and detail rebuild the sentence",
              "reason" not in row)
    log_check("the command line does not sit in the judgment",
              "command" not in row)
    log_check("head is the first line of the body, for tail(1)",
              row.get("head") == "rm -rf /tmp/x")
    log_check("bytes measures the body", row.get("bytes") == 13)
    body = os.path.join(bodies, row.get("ref") or "missing")
    log_check("the body holds the command line",
              os.path.exists(body)
              and open(body, encoding="utf-8").read() == "rm -rf /tmp/x")
    log_check("judgment logs cwd", row.get("cwd") == "/srv/project")
    log_check("judgment prints no decision", out == "")
    log_check("the judgment file is not world-readable",
              (os.stat(logfile).st_mode & 0o077) == 0)
    log_check("the bodies directory is not world-readable",
              (os.stat(bodies).st_mode & 0o077) == 0)
    log_check("a body is not world-readable",
              (os.stat(body).st_mode & 0o077) == 0)

    out = run_main("ls -la")
    log_check("allowed command prints allow", '"allow"' in out)
    log_check("allowed command is not recorded", len(read_log(logfile)) == 1)

    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = "off"
    run_main("rm -rf /tmp/y")
    log_check("logging honours off switch", len(read_log(logfile)) == 1)
    log_check("off switch reported by log_path",
              readonly_cmd.log_path() is None)
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile

    # The judgments file is a regression suite now, and rotating one deletes
    # test cases two cycles later. Only the bodies have a ceiling.
    with open(logfile, "a", encoding="utf-8") as fh:
        fh.write("x" * (2 * 1024 * 1024 + 1) + "\n")
    _before = count_lines(logfile)
    run_main("sed -i s/a/b/ f")
    log_check("an oversized judgment file does not rotate",
              not os.path.exists(logfile + ".1"))
    log_check("an oversized judgment file still appends",
              count_lines(logfile) == _before + 1)

    # Bodies are collected oldest first, in their own directory so this cannot
    # take the ones the checks above depend on.
    _gc_log = os.path.join(_tmp, "gc", "judgments.jsonl")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _gc_log
    _saved_max = readonly_cmd.BODIES_MAX_BYTES
    readonly_cmd.BODIES_MAX_BYTES = 200
    try:
        for _i in range(12):
            run_main("sed -i s/a%02d/b/ %s" % (_i, "f" * 40))
        _gc_bodies = os.path.join(_tmp, "gc", "bodies")
        _total = sum(os.path.getsize(os.path.join(_gc_bodies, n))
                     for n in os.listdir(_gc_bodies))
        log_check("bodies stay under the ceiling",
                  _total <= readonly_cmd.BODIES_MAX_BYTES)
        log_check("collecting bodies keeps every judgment",
                  count_lines(_gc_log) == 12)
    finally:
        readonly_cmd.BODIES_MAX_BYTES = _saved_max
        os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile

    # A log that cannot be written must not change the decision or raise.
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(_tmp, "nope", "d.jsonl")
    log_check("unwritable log stays silent on deny",
              run_main("rm -rf /tmp/z") == "")
    log_check("unwritable log still allows", '"allow"' in run_main("ls"))
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = logfile

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

    # replay is the one primitive: every reporter below is a caller of it.
    _records = readonly_cmd.load_judgments(logfile)
    _verdicts = readonly_cmd.replay(_records)
    log_check("replay answers once per record, in order",
              len(_verdicts) == len(_records))
    log_check("load_judgments fills the body back in",
              all(r.get("command") for r in _records))
    log_check("replay re-judges instead of reading the stored rule",
              _verdicts[0] and _verdicts[0]["rule"] == "known write/exec command")
    os.remove(os.path.join(bodies, _records[0]["ref"]))
    _gone = readonly_cmd.load_judgments(logfile)
    log_check("a collected body leaves its judgment behind",
              "command" not in _gone[0])
    log_check("replay says the body is gone rather than guessing",
              readonly_cmd.replay(_gone)[0]["rule"] == "body unavailable")

    # --open is the read list: admissions only, never a proven write.
    _open_log = os.path.join(_tmp, "open", "judgments.jsonl")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _open_log
    run_main("docker ps")
    run_main("echo x > f")
    _code, _text = capture(readonly_cmd.open_report)
    log_check("--open succeeds", _code == 0)
    log_check("--open keeps what the parser did not recognise",
              "docker" in _text)
    log_check("--open drops what the parser proved writes",
              "echo x" not in _text and "output redirection" not in _text)

    # --regress compares the stored judgment with today's, both directions.
    _reg_log = os.path.join(_tmp, "regress", "judgments.jsonl")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _reg_log
    readonly_cmd.record_judgment("strings f", readonly_cmd.UNKNOWN_COMMAND_RULE,
                                 "strings")
    readonly_cmd.record_judgment("rm -rf /x", readonly_cmd.CLASSIFIER_ALLOW_RULE,
                                 "rm")
    _code, _text = capture(readonly_cmd.regress)
    log_check("--regress succeeds", _code == 0)
    log_check("--regress reports a refusal that now passes", "strings f" in _text)
    log_check("--regress reports a pass that is now refused", "rm -rf /x" in _text)

    # A collected body is not a change of mind. Counted as one, it fills the
    # list that exists to be read line by line.
    _stale_log = os.path.join(_tmp, "stale", "judgments.jsonl")
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _stale_log
    readonly_cmd.record_judgment("docker ps", readonly_cmd.CLASSIFIER_ALLOW_RULE,
                                 "docker")
    os.remove(os.path.join(_tmp, "stale", "bodies",
                           read_log(_stale_log)[0]["ref"]))
    _code, _text = capture(readonly_cmd.regress)
    log_check("--regress sets a collected body aside rather than calling it a flip",
              "auto-allowed -> refused: 0" in _text
              and "1 skipped (body collected)" in _text)
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _reg_log

    # --report counts replay verdicts and names the promotion candidates.
    _code, _text = capture(readonly_cmd.report)
    log_check("--report succeeds", _code == 0)
    log_check("--report counts what replay decided",
              "judgments" in _text and "auto-allowed" in _text)
    log_check("--report names the classifier verdicts still unexpressed",
              "rm" in _text)

    # --migrate is replay with a destination: what the parser now settles by
    # itself is not carried over, in either direction.
    _mig = os.path.join(_tmp, "migrate")
    os.makedirs(_mig)
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(_mig,
                                                         "judgments.jsonl")
    with open(os.path.join(_mig, "denied.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(_json.dumps({"ts": "2026-01-01T00:00:00+0900",
                              "rule": "command not on read-only allowlist",
                              "detail": "docker",
                              "reason": "command not on read-only allowlist",
                              "command": "docker ps"}) + "\n")
        fh.write(_json.dumps({"ts": "2026-01-01T00:00:01+0900",
                              "rule": "command not on read-only allowlist",
                              "detail": "strings",
                              "reason": "command not on read-only allowlist",
                              "command": "strings f"}) + "\n")
        fh.write(_json.dumps({"ts": "2026-01-01T00:00:02+0900",
                              "rule": "output redirection to",
                              "detail": "f"}) + "\n")
        fh.write("not json\n")
    with open(os.path.join(_mig, "allowed.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(_json.dumps({"ts": "2026-01-02T00:00:00+0900",
                              "name": "docker",
                              "command": "docker images"}) + "\n")
        fh.write(_json.dumps({"ts": "2026-01-02T00:00:01+0900",
                              "name": "strings",
                              "command": "strings g"}) + "\n")
    _code, _text = capture(readonly_cmd.migrate)
    _rows = read_log(os.path.join(_mig, "judgments.jsonl"))
    _heads = [r.get("head") for r in _rows]
    log_check("--migrate succeeds", _code == 0)
    log_check("migrate carries a denial that still stands",
              "docker ps" in _heads)
    log_check("migrate drops a denial the parser now allows",
              "strings f" not in _heads)
    log_check("migrate keeps a classifier verdict the parser still needs",
              any(r.get("rule") == readonly_cmd.CLASSIFIER_ALLOW_RULE
                  and r.get("head") == "docker images" for r in _rows))
    log_check("migrate drops a classifier verdict the parser absorbed",
              "strings g" not in _heads)
    log_check("migrate counts a bodyless legacy line apart from the drops",
              "skipped: 1 legacy lines carried no command" in _text)
    log_check("migrate keeps the original timestamp",
              [r for r in _rows if r.get("head") == "docker ps"][0]["ts"]
              == "2026-01-01T00:00:00+0900")
    log_check("migrate re-judges rather than copying the stored rule",
              [r for r in _rows if r.get("head") == "docker ps"][0]["rule"]
              == readonly_cmd.UNKNOWN_COMMAND_RULE)
    log_check("migrate sets the originals aside",
              os.path.exists(os.path.join(_mig, "denied.jsonl.0"))
              and os.path.exists(os.path.join(_mig, "allowed.jsonl.0")))
    capture(readonly_cmd.migrate)
    log_check("a second migrate has nothing left to move",
              len(read_log(os.path.join(_mig, "judgments.jsonl")))
              == len(_rows))

    # Default location: its own directory, not loose in the config root.
    os.environ.pop("PLAN_MODE_AUTOALLOW_LOG", None)
    os.environ["CLAUDE_CONFIG_DIR"] = _tmp
    log_check("default log sits in its own directory",
              readonly_cmd.log_path() == os.path.join(
                  _tmp, "plan-mode-autoallow", "judgments.jsonl"))
    os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(
        _tmp, "made", "up", "judgments.jsonl")
    run_main("rm -rf /tmp/w")
    log_check("missing parent directories are created",
              os.path.exists(os.path.join(_tmp, "made", "up",
                                          "judgments.jsonl")))
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

# --- LLM tier. The classifier itself is replaced with a stub: what is worth
# --- testing here is the routing around it, and that has to stay deterministic.
# --- Whether the real model answers well is a separate question, measured by
# --- tests/eval_llm.py against live calls.
llm_checks = []


def llm_check(name, ok):
    llm_checks.append((name, ok))


class FakeClassifier(object):
    """Stands in for `claude -p`, recording whether it was consulted at all."""

    def __init__(self, answer):
        self.answer = answer
        self.asked = []

    def __call__(self, command):
        self.asked.append(command)
        return self.answer


def with_classifier(answer, command, enabled=True, cwd=None):
    saved_call, saved_env = rc.llm_says_read_only, os.environ.get(rc.LLM_ENV)
    fake = FakeClassifier(answer)
    rc.llm_says_read_only = fake
    os.environ[rc.LLM_ENV] = "on" if enabled else "off"
    try:
        verdict = rc.explain(command)
        allowed = (verdict is not None
                   and rc.llm_second_opinion(command, verdict, cwd))
        return allowed, fake.asked
    finally:
        rc.llm_says_read_only = saved_call
        if saved_env is None:
            os.environ.pop(rc.LLM_ENV, None)
        else:
            os.environ[rc.LLM_ENV] = saved_env


_llm_tmp = tempfile.mkdtemp(prefix="autoallow-llm-")
_llm_saved = os.environ.get("PLAN_MODE_AUTOALLOW_LOG")
os.environ["PLAN_MODE_AUTOALLOW_LOG"] = os.path.join(_llm_tmp,
                                                     "judgments.jsonl")
try:
    allowed, asked = with_classifier(True, "docker ps")
    llm_check("a yes on an unknown command allows it", allowed and asked)

    allowed, asked = with_classifier(False, "terraform apply")
    llm_check("a no leaves the command at the prompt", not allowed and asked)

    allowed, asked = with_classifier(True, "cargo build", enabled=False)
    llm_check("off by default: not consulted, not allowed",
              not allowed and not asked)

    # Structural denials never reach the classifier: those rules are the whole
    # job of the parser, and a model does not get a vote on them.
    for line in ("echo hi > /tmp/o", "cat `id`", "eval ls", "python3 -c x",
                 "cat <(id)"):
        allowed, asked = with_classifier(True, line)
        llm_check("structural denial is not referred out: %s" % line,
                  not allowed and not asked)

    for name in ("rm -rf /tmp/x", "sudo ls", "chmod 777 f", "sh -c id",
                 "kill 1", "mkfs.ext4 /dev/sda", "fsck.ext4 /dev/sda"):
        allowed, asked = with_classifier(True, name)
        llm_check("a known executor is not referred out: %s" % name,
                  not allowed and not asked)

    # A yes buys one command name, not a pass on the rest of the line.
    for line in ("docker ps | rm -rf /tmp/x", "docker ps && cd /tmp && git log"):
        allowed, _ = with_classifier(True, line)
        llm_check("re-run still applies every other rule: %s" % line,
                  not allowed)

    allowed, _ = with_classifier(True, "docker ps | grep foo")
    llm_check("the rest of the line may be ordinary read-only commands", allowed)

    # ALWAYS_OK is mutated for the re-run and must not stay mutated.
    llm_check("the vouched-for name does not leak into the allowlist",
              "docker" not in rc.ALWAYS_OK
              and rc.explain("docker ps") is not None)

    _judgments = rc.log_path()
    _rows = [r for r in read_log(_judgments)
             if r.get("rule") == rc.CLASSIFIER_ALLOW_RULE]
    llm_check("the verdict goes in the same log as every other judgment",
              _rows and _rows[0]["detail"] == "docker"
              and _rows[0]["head"] == "docker ps")

    # A cached verdict stands on its own, without asking again.
    allowed, asked = with_classifier(False, "docker ps")
    llm_check("a cached yes is reused and the model is not consulted",
              allowed and not asked)

    # The body is the cache. Collect it and the question is asked again rather
    # than answered from a line that no longer proves which command it was.
    os.remove(os.path.join(rc.bodies_dir(_judgments), _rows[0]["ref"]))
    allowed, asked = with_classifier(True, "docker ps")
    llm_check("a collected body is a cache miss, not a stale hit",
              allowed and asked)
finally:
    if _llm_saved is None:
        os.environ.pop("PLAN_MODE_AUTOALLOW_LOG", None)
    else:
        os.environ["PLAN_MODE_AUTOALLOW_LOG"] = _llm_saved
    shutil.rmtree(_llm_tmp, ignore_errors=True)

llm_fail = 0
for _name, _ok in llm_checks:
    if not _ok:
        print("FAIL (llm): %s" % _name)
        llm_fail += 1
print("llm: %d/%d passed" % (len(llm_checks) - llm_fail, len(llm_checks)))


# --- appended: the scratchpad exception. Every write was refused, which is
# --- right for the project tree and wrong for the one directory a read-only
# --- planner has to write in -- `explore-model` builds a throwaway harness
# --- under the session scratchpad and reruns it as the model is corrected, so
# --- each rewrite was costing an approval the skill was written to avoid.
# --- Writes whose destination is provably inside that directory are allowed.
# --- Running what was written is not: the parser cannot read a script, and
# --- allowing both halves turns the pair into arbitrary code execution inside
# --- plan mode. That asymmetry is the rule, so both halves are tested here.

_SC = ("/tmp/claude-1000/-home-user-proj/"
       "6c5bce46-7e93-42d5-ad24-4b1533001932/scratchpad")

SCRATCH = [
    # writes landing inside the scratchpad
    ("echo hi > %s/out.txt" % _SC, None),
    ("grep -rn foo src/ >> %s/log.txt" % _SC, None),
    ("gh issue view 1 --json title > %s/i.json" % _SC, None),
    ("cat > %s/h.py <<'EOF'\nSTATES = []\nEOF" % _SC, None),
    ('cat > %s/h.py <<"EOF"\nSTATES = []\nEOF' % _SC, None),
    ("cat > %s/h.py <<-'EOF'\n\tx\n\tEOF" % _SC, None),
    # running what was written stays a prompt -- this is the half that must not
    # open, or the two together are arbitrary code execution
    ("python3 %s/h.py" % _SC, "known write/exec command"),
    ("bash %s/h.py" % _SC, "known write/exec command"),
    # an unquoted delimiter expands `$(...)` in the body: that body is code
    ("cat > %s/h.py <<EOF\nx\nEOF" % _SC, "heredoc"),
    # heredoc ahead of the redirect -- the flag cannot be set by a redirect the
    # tokenizer has not reached yet, so this stays refused on purpose
    ("cat <<'EOF' > %s/h.py\nx\nEOF" % _SC, "heredoc"),
    # a heredoc with no scratchpad write anywhere on the line
    ("bash <<'EOF'\nrm -rf /\nEOF", "heredoc"),
    # destinations that only look like the scratchpad
    ("echo x > %s/../../../etc/passwd" % _SC, "output redirection to"),
    ("echo x > /tmp/evil.sh", "output redirection to"),
    ("echo x > /tmp/claude-1000/scratchpad/x", "output redirection to"),
    ("echo x > /tmp/claude-abc/p/s/scratchpad/x", "output redirection to"),
    ("echo x > %s/" % _SC, "output redirection to"),
    # the body is dropped from the token stream, so what is left still has to
    # clear every other rule
    ("rm -rf src/ > %s/out.txt" % _SC, "known write/exec command"),
    # The exception reads the target token as written -- the tokenizer expands
    # nothing -- so it fires on a literal absolute path and on nothing else.
    # Every form below resolves to the same directory at runtime and still
    # prompts. That is the boundary, and it is pinned here rather than left to
    # be rediscovered: the numbers this exception is justified by were measured
    # with literal paths, and a reader comparing them against a session full of
    # `S=...; cat > "$S/h.py"` would find them off by the whole benefit.
    #
    # Resolving the assignment was considered and refused. Over the judgment
    # log's lifetime (324 records, 115 write refusals) the literal form
    # accounts for 9 and the same-line variable form for 3, so the win is 3 --
    # against giving the parser a symbol table it deliberately does not have
    # ("assignment-only segments set a shell variable and run nothing"). The
    # failure directions decide it: today a form it cannot read prompts, which
    # is safe; a resolver that reads one wrong allows a write, which is not.
    # The friction is answered on the other side instead -- the planner is told
    # to write harness paths literally.
    #
    # Cross-call assignment needs no rule at all: the Bash tool does not carry
    # shell state between calls, so `S=` in one call leaves `$S` empty in the
    # next. Only the same-line form ever meant anything.
    ('S=%s; echo x > "$S/out.txt"' % _SC, "output redirection to"),
    ("S=%s; echo x > $S/out.txt" % _SC, "output redirection to"),
    ('S=%s; echo x > "${S}/out.txt"' % _SC, "output redirection to"),
    ("S=%s; cat > \"$S/h.py\" <<'EOF'\nx\nEOF" % _SC, "output redirection to"),
    ("echo x > ./out.txt", "output redirection to"),
    ("echo x > ~/scratch/out.txt", "output redirection to"),
]
scratch_fail = 0
for _cmd, _rule in SCRATCH:
    _v = rc.explain(_cmd)
    if (_v is None) != (_rule is None) or (_v and _v["rule"] != _rule):
        print("FAIL (scratchpad, want %r): %r -> %r" % (_rule, _cmd, _v))
        scratch_fail += 1
print("scratchpad: %d/%d passed" % (len(SCRATCH) - scratch_fail, len(SCRATCH)))


# --- appended: what holds the scratchpad exception shut. is_scratch_path is
# --- lexical -- it never resolves the path -- so a symlink inside the
# --- scratchpad pointing out of it would be written through. Nothing here
# --- tests that, because it is true and is meant to be: what makes it
# --- unreachable is that planting the link is refused. This bucket pins that
# --- refusal, and pins WHICH KIND it is, because the two kinds have different
# --- strength.
# ---
# --- A structural refusal cannot be talked out of: llm_second_opinion returns
# --- early unless the rule is UNKNOWN_COMMAND_RULE, so a classifier YES never
# --- reaches these lines. An unknown-name refusal is only as strong as the
# --- classifier's judgment on that name -- the parser has no opinion about
# --- `tar`, and a YES there would open the line. The real classifier refused
# --- all six (measured, 2026-09-02), but that is a vote, not a proof, and the
# --- split is what a reader needs to see. Promoting them the way `unzip` was
# --- promoted -- a flag checker, since `tar tf` reads and `tar xf` writes --
# --- is what would move them across the line.

SYMLINK_STRUCTURAL = [
    ("ln -s /etc/passwd %s/link" % _SC, "known write/exec command"),
    ("ln -sf /etc/passwd %s/link" % _SC, "known write/exec command"),
    ("cp -s /etc/passwd %s/link" % _SC, "known write/exec command"),
    ("install -s /etc/passwd %s/link" % _SC, "known write/exec command"),
    ("python3 -c \"import os; os.symlink('/etc/passwd','%s/l')\"" % _SC,
     "known write/exec command"),
    ("unzip evil.zip -d %s" % _SC, "unzip without a list flag extracts"),
    ("unzip -o evil.zip", "unzip without a list flag extracts"),
    ("git checkout other -- .", "known write/exec git subcommand"),
    ("git clone https://example.com/r.git %s/r" % _SC,
     "known write/exec git subcommand"),
    ("gh repo clone o/r %s/r" % _SC, "known write/exec gh subcommand"),
]
# The classifier is the only gate on these. Listed so that promoting one to the
# allowlist trips this test instead of quietly opening the link path.
SYMLINK_CLASSIFIER_GATED = [
    "tar xf evil.tar -C %s" % _SC,
    "tar -xzf evil.tgz",
    "rsync -a src/ %s/d/" % _SC,
    "cpio -i < a.cpio",
    "7z x evil.7z",
    "bsdtar xf evil.tar",
    "busybox ln -s /etc/passwd %s/link" % _SC,
]
symlink_fail = 0
for _cmd, _rule in SYMLINK_STRUCTURAL:
    _v = rc.explain(_cmd)
    if not _v or _v["rule"] != _rule:
        print("FAIL (symlink structural, want %r): %r -> %r"
              % (_rule, _cmd, _v))
        symlink_fail += 1
for _cmd in SYMLINK_CLASSIFIER_GATED:
    _v = rc.explain(_cmd)
    if not _v or _v["rule"] != rc.UNKNOWN_COMMAND_RULE:
        print("FAIL (symlink classifier-gated, want unknown name): %r -> %r"
              % (_cmd, _v))
        symlink_fail += 1
_symlinks = len(SYMLINK_STRUCTURAL) + len(SYMLINK_CLASSIFIER_GATED)
print("symlink: %d/%d passed" % (_symlinks - symlink_fail, _symlinks))


total = (len(ALLOW) + len(DENY) + len(EXTRA) + len(HARDENING) + len(GH)
         + _tools + len(GITPROMOTE) + len(KNOWN_EXEC)
         + len(KNOWN_SUB) + len(open_checks) + len(cdgit_checks)
         + len(log_checks) + len(llm_checks) + len(SCRATCH) + _symlinks)
total_fail = (fails + extra_fail + hard_fail + gh_fail + tool_fail
              + promote_fail + known_fail + sub_fail + open_fail
              + cdgit_fail + log_fail + llm_fail + scratch_fail
              + symlink_fail)
print("TOTAL: %d/%d passed" % (total - total_fail, total))
sys.exit(1 if total_fail else 0)
