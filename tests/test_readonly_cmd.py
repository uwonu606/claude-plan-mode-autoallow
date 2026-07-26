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

total = len(ALLOW) + len(DENY) + len(EXTRA) + len(HARDENING)
total_fail = fails + extra_fail + hard_fail
print("TOTAL: %d/%d passed" % (total - total_fail, total))
sys.exit(1 if total_fail else 0)
