#!/usr/bin/env python3
"""Decide whether a Bash command is read-only, for the plan-mode PreToolUse hook.

Reads the raw PreToolUse hook JSON on stdin. Prints an "allow" hook decision
only when every command in the (possibly compound) shell line is on a
read-only allowlist. Stays silent otherwise, which leaves the normal
permission prompt in place.

Default deny: anything unparseable, unknown, or ambiguous falls through to
the prompt. The threat model is "keep the agent from accidentally running a
destructive command while planning", not defense against a crafted bypass.
"""

import json
import sys

# `re` is imported lazily inside check_sed_script: it costs ~4ms of startup and
# only the sed path needs it, and this runs on every plan-mode Bash call.

# ---------------------------------------------------------------- allowlists

ALWAYS_OK = {
    "ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "fd",
    "tree", "file", "stat", "du", "df", "diff", "uniq", "cut", "jq", "which",
    "type", "pwd", "basename", "dirname", "realpath", "readlink",
    "echo", "printf", "true", "false", "test", "[", "[[", "seq", "column",
    "comm", "join", "paste", "nl", "tac", "rev", "md5sum", "sha256sum",
    # `hostname` is absent on purpose: with an operand or -F it renames the
    # host. Reading the name is already covered by `uname -n`.
    "cksum", "cd", "pushd", "popd", "uname", "whoami", "id",
    "groups", "ps", "locale", "tty", "printenv", "wait", "sleep", "expr",
    # Present in Claude Code's own read-only set (extracted from the 2.1.220
    # binary) and absent here until now.
    "strings", "hexdump", "od", "tr", "cmp", "fold", "expand", "unexpand",
    "fmt", "numfmt", "pr", "tsort", "cal", "nproc", "free", "uptime",
}

# Wrappers whose real command follows; the wrapped command is validated
# recursively. `ionice`, `watch`, `setsid`, `flock` and `nohup` are absent on
# purpose -- Claude Code always prompts for those, so they stay unlisted and
# therefore denied.
WRAPPERS = {"timeout", "nice", "stdbuf", "command", "builtin", "env"}

SHELL_KEYWORDS_SKIP = {"do", "done", "then", "else", "fi", "esac", "in", "!",
                       "time", "{", "}"}
SHELL_KEYWORDS_STRIP = {"while", "until", "if", "elif"}
SHELL_KEYWORDS_WORDLIST = {"for", "select", "case"}

GIT_READ_SUBCOMMANDS = {
    "status", "log", "diff", "show", "branch", "remote", "rev-parse",
    "ls-files", "ls-remote", "ls-tree", "blame", "describe", "cat-file",
    "for-each-ref", "shortlog", "config", "grep", "reflog", "rev-list",
    "show-ref", "count-objects", "var", "whatchanged", "check-ignore",
    "worktree", "merge-base",
}
# The same test KNOWN_EXECUTORS applies, one level down: does the name settle
# the verdict on its own? `git fetch` moves refs whatever follows it, the way
# `rm` deletes whatever follows it -- that `--dry-run` exists no more makes
# `push` a reader than `python3 -c "print(1)"` makes python3 one. Without this
# the parser said only "git: fetch", the same sentence it says for a subcommand
# it has never heard of, and a settled write sat in the unresolved pile every
# cycle. Names with an ordinary read form are deliberately absent -- `git tag`
# lists tags, `git stash list` and `git submodule status` read -- because
# calling those writes would bury a real promotion question.
GIT_WRITE_SUBCOMMANDS = {
    "add", "am", "checkout", "cherry-pick", "clean", "clone", "commit",
    "commit-tree", "fast-import", "fetch", "filter-branch", "gc", "init",
    "merge", "mktree", "mv", "prune", "pull", "push", "rebase", "repack",
    "reset", "restore", "revert", "rm", "switch", "update-index",
    "update-ref", "write-tree",
}

# gh names the act in the second word, so the pair is what settles it.
GH_WRITE_ACTIONS = {
    "auth": {"login", "logout", "switch", "refresh", "setup-git", "token"},
    "pr": {"create", "merge", "close", "reopen", "edit", "review", "comment",
           "ready", "checkout", "lock", "unlock"},
    "issue": {"create", "close", "reopen", "edit", "comment", "delete",
              "pin", "unpin", "transfer", "lock", "unlock"},
    "repo": {"create", "delete", "fork", "clone", "edit", "rename",
             "archive", "unarchive", "sync", "deploy-key"},
    "release": {"create", "delete", "edit", "upload", "download"},
    "secret": {"set", "delete"},
    "variable": {"set", "delete"},
    "workflow": {"run", "enable", "disable"},
    "run": {"rerun", "cancel", "delete", "download"},
    "gist": {"create", "delete", "edit", "clone"},
    "label": {"create", "delete", "edit", "clone"},
    "cache": {"delete"},
    "alias": {"set", "delete", "import"},
    "config": {"set"},
    "extension": {"install", "remove", "upgrade", "create"},
    "codespace": {"create", "delete", "stop", "rebuild", "edit"},
    "ssh-key": {"add", "delete"},
    "gpg-key": {"add", "delete"},
}

GIT_FLAGS_WITH_VALUE = {"-C", "--git-dir", "--work-tree", "--namespace"}
GIT_BRANCH_MUTATE = {"-d", "-D", "-m", "-M", "-c", "-C", "-f", "--delete",
                     "--move", "--copy", "--force", "--unset-upstream",
                     "--edit-description"}

# Verbs that read the remote configuration, which is where a `remote.<n>.url`
# of `ext::sh -c ...` turns into an execution. Everything else in the read set
# above never looks at it, and that is what lets the `cd` inspection below skip
# the `remote` section entirely. Most of these are already refused as write
# subcommands; the two that matter here are `ls-remote` and `remote`.
GIT_NETWORK_SUBCOMMANDS = {"fetch", "pull", "push", "clone", "ls-remote",
                           "remote", "submodule", "archive"}

# Sections git itself reads a value out of. Outside them the key is inert
# whatever it says -- third-party tools park their own keys in a repo's local
# config (`branch.<n>.vscode-merge-base`, `remote.origin.glab-resolved-head`,
# `lfs.*`) and treating an unknown key as a dangerous one refuses every real
# repository. See docs/adr/0002.
GIT_CONFIG_SECTIONS_READ = {
    "core", "alias", "include", "includeif", "diff", "difftool", "merge",
    "mergetool", "filter", "credential", "http", "ssh", "url", "uploadpack",
    "receivepack", "protocol", "gpg", "sendemail", "pager", "man", "help",
    "browser", "guitool", "instaweb", "sequence", "imap", "svn", "svn-remote",
    "trace2", "safe", "fsmonitor", "web",
}
# Inside a watched section, only these keys are accepted. They are what `git
# init` writes and none of them names a program or a path git will run.
GIT_CONFIG_KEYS_OK = {
    "core.repositoryformatversion", "core.filemode", "core.bare",
    "core.logallrefupdates", "core.symlinks", "core.ignorecase",
    "core.precomposeunicode",
}
GIT_CONFIG_TRUE = {"", "true", "yes", "on", "1"}
GIT_INSPECT_TIMEOUT = 5

# javap's -J passes an option through to the JVM (`-J-javaagent:evil.jar`), so
# the flags are allowlisted. The single-dash long flags are matched whole,
# which the walk below does before it starts splitting a word into letters.
JAVAP_FLAGS_OK = {
    "-c", "-p", "-s", "-l", "-v", "-verbose", "-public", "-protected",
    "-package", "-private", "-constants", "-sysinfo",
    "-help", "--help", "-version", "--version",
}
JAVAP_FLAGS_WITH_VALUE = {"--class-path", "--module-path", "--system",
                          "--module", "--multi-release"}
# Single-dash flags that take the next word. They are consumed before the walk
# because the per-letter pass would read `-cp` as the bundle `-c -p` and then
# mistake the classpath for a class name.
JAVAP_FLAGS_TAKING_NEXT = {"-cp", "-classpath", "-bootclasspath", "-m"}

# unzip's default action is to extract, so a listing flag is required rather
# than merely permitted. `-Z` is zipinfo mode and `-c` writes to stdout;
# neither puts anything on disk.
UNZIP_LIST_FLAGS = {"-l", "-p", "-t", "-z", "-v", "-Z", "-c"}
UNZIP_FLAGS_OK = UNZIP_LIST_FLAGS | {"-q", "-C", "-M"}
UNZIP_FLAGS_WITH_VALUE = {"-x", "-P"}

# curl is allowlisted in the same direction and for the same reason as `sort`:
# the flags that write do not look like actions. -o and -O write a file, -D and
# -c write a header/cookie file, -K reads a config file that can carry
# `output=`, and -d/-F/-T/-X send a mutating request. An unknown flag is
# refused rather than enumerated.
CURL_FLAGS_OK = {
    "-s", "--silent", "-S", "--show-error", "-L", "--location",
    "-I", "--head", "-i", "--include", "-f", "--fail", "--fail-with-body",
    "-k", "--insecure", "-v", "--verbose", "-g", "--globoff",
    "-N", "--no-buffer", "-4", "-6", "--compressed", "--no-progress-meter",
    "--http1.1", "--http2", "--help", "--version",
}
CURL_FLAGS_WITH_VALUE = {
    "-H", "--header", "-m", "--max-time", "--connect-timeout",
    "-A", "--user-agent", "-e", "--referer", "-x", "--proxy",
    "--retry", "--retry-delay", "--retry-max-time", "--resolve",
    "--limit-rate", "-b", "--cookie", "--url",
}

FIND_BAD = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls",
            "-files0-from"}

# `sort`, `file` and `awk` are screened by listing the flags that are allowed
# rather than the ones that are not. All three were picked for that treatment by
# being caught: `file -C` writes magic.mgc, `sort --compress-program=sh` runs a
# program, and gawk writes files through -o/-p/-d and loads shared objects
# through -l. None of those look like an action flag, which is what a denylist
# needs them to look like. The tools whose dangerous surface really is a short
# closed list -- find's actions, rg's --pre, fd's --exec -- keep their denylists
# below; an allowlist there would mean enumerating fifty harmless predicates and
# refusing every one that got left out.
SORT_FLAGS_OK = {
    "-b", "-d", "-f", "-g", "-i", "-M", "-h", "-n", "-R", "-r", "-s", "-u",
    "-z", "-c", "-C", "-m", "--ignore-leading-blanks", "--dictionary-order",
    "--ignore-case", "--general-numeric-sort", "--ignore-nonprinting",
    "--month-sort", "--human-numeric-sort", "--numeric-sort", "--random-sort",
    "--reverse", "--stable", "--unique", "--zero-terminated", "--check",
    "--merge", "--debug", "--help", "--version",
}
SORT_FLAGS_WITH_VALUE = {
    "-k", "--key", "-t", "--field-separator", "-T", "--temporary-directory",
    "-S", "--buffer-size", "--parallel", "--batch-size", "--files0-from",
    "--random-source", "--sort",
}

FILE_FLAGS_OK = {
    "-b", "--brief", "-c", "--checking-printout", "--exclude-quiet",
    "-i", "--mime", "--mime-encoding", "--mime-type", "--apple", "--extension",
    "-k", "--keep-going", "-l", "--list", "-L", "--dereference",
    "-h", "--no-dereference", "-n", "--no-buffer", "-N", "--no-pad",
    "-0", "--print0", "-p", "--preserve-date", "-r", "--raw",
    "-s", "--special-files", "-d", "--debug", "-v", "--version", "--help",
}
FILE_FLAGS_WITH_VALUE = {"-e", "--exclude", "-F", "--separator",
                         "-P", "--parameter"}

# -S disables file(1)'s own seccomp sandbox and -z/-Z hand the payload to
# external decompressors, so neither is listed above even though both read.
AWK_FLAGS_OK = {"--posix", "--traditional", "-c", "--re-interval",
                "-b", "--characters-as-bytes", "-S", "--sandbox",
                "--help", "--version"}
AWK_FLAGS_WITH_VALUE = {"-F", "--field-separator", "-v", "--assign"}
AWK_PROGRAM_FLAGS = {"-e", "--source"}

# `date` needs an allowlist for a reason the other three do not share: on
# BSD/macOS it takes the new clock value as a bare operand, with no flag at all
# (`date 010100002026`). Refusing -s and --set only covers GNU. Everything date
# prints goes through a `+FORMAT` operand, so anything else is a set.
DATE_FLAGS_OK = {
    "-u", "--utc", "--universal", "-R", "--rfc-email", "--iso-8601",
    "--rfc-3339", "--debug", "--help", "--version",
    "-I", "-Idate", "-Ihours", "-Iminutes", "-Iseconds", "-Ins",
}
DATE_FLAGS_WITH_VALUE = {"-d", "--date", "-f", "--file",
                         "-r", "--reference"}

# jq can read arbitrary files and load modules: -f/--from-file, --rawfile,
# --slurpfile, -L/--library-path, --run-tests, and `env`/`$ENV`/`include`/
# `import` inside the program.
JQ_BAD_FLAGS = {"-f", "--from-file", "--rawfile", "--slurpfile", "-L",
                "--library-path", "--run-tests", "--args", "--jsonargs"}
JQ_BAD_PROGRAM = ("$env", "$ENV", "include ", "import ", "input_filename",
                  "getpath", "$__loc__")

# awk can write files (`print > "f"`), pipe into a shell (`print | "sh"`) and
# execute (`system()`), so the program text is screened hard: any redirection
# or pipe operator disqualifies it, even when it was meant as a comparison.
AWK_BAD = ("system", "close(", "environ", "/dev/std", "getline", "|", "fflush",
           "printf(", "|&")

# sed can write files (`w FILE`, `s///w FILE`) and execute (`e`, `s///e`), none
# of which the -i check catches. Only these script shapes are accepted.
SED_SAFE_PATTERNS = (
    r"^\s*[0-9]+(?:\s*,\s*(?:[0-9]+|\$))?\s*[pdq=]\s*$",
    r"^\s*\$\s*[pdq=]\s*$",
    r"^\s*/(?:[^/\\]|\\.)*/\s*[pd]\s*$",
    r"^\s*s(.)(?:[^\\]|\\.)*?\1(?:[^\\]|\\.)*?\1[gpiImM0-9]*\s*$",
)
SED_FLAGS_OK = {"-n", "-E", "-r", "-z", "-u", "-s", "--quiet", "--silent",
                "--regexp-extended", "--null-data", "--separate", "--posix"}

FD_BAD = {"-x", "-X", "--exec", "--exec-batch"}

# `gh api` is a raw authenticated client for the whole GitHub API, so what it
# can do equals the token's scopes. Only GET/HEAD is accepted. Note that gh
# switches to POST as soon as any request field is present, so field flags are
# rejected unless the method is explicitly GET/HEAD.
GH_API_FIELD_FLAGS = {"-f", "--raw-field", "-F", "--field"}
GH_API_VALUE_FLAGS = {"-H", "--header", "-p", "--preview", "-q", "--jq",
                      "-t", "--template", "--cache", "--hostname", "--slurp"}
GH_READ_SUBCOMMANDS = {
    "repo": {"view", "list"},
    "pr": {"view", "list", "diff", "status", "checks"},
    "issue": {"view", "list", "status"},
    "run": {"view", "list"},
    "workflow": {"view", "list"},
    "release": {"view", "list"},
    "gist": {"view", "list"},
    "label": {"list"},
    "search": {"repos", "issues", "prs", "code", "commits"},
    "auth": {"status"},
    "cache": {"list"},
    "extension": {"list"},
    "org": {"list"},
    "status": set(),
    "version": set(),
}

REDIR_OK_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr"}

# The session scratchpad is the one writable place a read-only planner needs.
# `explore-model` builds a throwaway harness there and reruns it as the model is
# corrected, and that skill's economics assume the rerun is cheap: "틀린 불변식의
# 비용은 탐색 재실행 몇 초라, 매 호출의 승인 왕복보다 싸다". With no exception here
# every rewrite is an approval round trip, which is the cost the skill was
# written to avoid.
#
# The shape is fixed by the harness -- /tmp/claude-<uid>/<project-slug>/<session
# -uuid>/scratchpad/... -- so this is an exact-depth check rather than a prefix
# test, and `..` anywhere disqualifies the path outright. A symlink planted
# inside the scratchpad would still resolve out of it, but planting one needs
# `ln`, which is a KNOWN_EXECUTOR and prompts.
#
# Matched with string operations, not a regex: `re` is imported lazily further
# down precisely because this module runs on every Bash call in plan mode, and a
# module-level import would put that cost on all of them.
SCRATCH_PREFIX = "/tmp/claude-"
SCRATCH_MARK = "/scratchpad/"


def is_scratch_path(target):
    """True for a path inside this machine's session scratchpad, and only that."""
    p = target.strip("\"'")
    if not p.startswith(SCRATCH_PREFIX) or ".." in p:
        return False
    mark = p.find(SCRATCH_MARK)
    if mark < 0 or not p[mark + len(SCRATCH_MARK):]:
        return False
    parts = p[:mark].split("/")
    # ['', 'tmp', 'claude-<uid>', '<project-slug>', '<session-uuid>']
    return (len(parts) == 5
            and parts[2][len("claude-"):].isdigit()
            and bool(parts[3]) and bool(parts[4]))


# Set when a redirect on the current line resolved into the scratchpad. It is
# what lets the heredoc branch tell `cat > <scratch>/h.py <<'EOF'` -- a harness
# being written -- from `bash <<'EOF'`, which is a script being run. Cleared per
# call in explain(), beside the other per-line state.
SCRATCH_REDIRECT = []

# rg can execute a preprocessor binary and read archives through helpers.
RG_BAD_FLAGS = {"--pre", "--pre-glob", "--hostname-bin", "-z", "--search-zip"}

# Commands whose flags can write or execute. An unquoted glob next to one of
# these is a hole: the glob can expand to a filename like `-delete` or
# `--output=x`. Claude Code applies the same rule.
GLOB_SENSITIVE = {"find", "sort", "sed", "git", "rg"}

# A `VAR=value cmd` prefix runs cmd with that variable set, which is an
# execution vector for a long tail of tools (PAGER, LD_PRELOAD, BASH_ENV,
# GIT_EXTERNAL_DIFF...). Only locale/formatting variables are accepted.
# Assignment-only segments (`n=${d%/}`) are unrestricted -- they set a shell
# variable and run nothing.
ENV_PREFIX_OK = {
    "LANG", "LANGUAGE", "TZ", "COLUMNS", "LINES", "TERM", "NO_COLOR",
    "CLICOLOR", "CLICOLOR_FORCE", "GREP_COLORS", "GREP_COLOR",
}

# `env` flags are allowlisted rather than denylisted, because the dangerous ones
# do not look dangerous: `-S` splits its operand into a whole command line
# (`env -S"touch x"` runs touch), and `-a` renames argv[0] so the command that
# gets validated is not the one that runs. A denylist has to know both in
# advance; this way an unrecognized flag is simply refused.
ENV_FLAGS_OK = {"-", "-i", "--ignore-environment", "-0", "--null",
                "-v", "--debug", "--help", "--version"}
ENV_FLAGS_WITH_VALUE = {"-u", "--unset"}

# Names the parser can settle without looking at a single argument. The
# membership rule is one thing rather than a feeling about each name: the name
# alone finishes the question. `rm` is a deletion whatever follows it, `sudo` is
# an escalation, `sh` runs whatever it is handed.
#
# Dispatchers are not on the list, and that includes the system-control ones.
# `systemctl`, `ip`, `iptables`, `sysctl` name a subject, not an act: the verb
# is the subcommand, and `systemctl status` is exactly as much a read as
# `docker ps`. Holding them back was worth reconsidering because the reason
# given -- that a wrong yes on `systemctl stop` is unusually bad -- does not
# survive comparison with `docker system prune -f` or `kubectl delete`, which
# the classifier already judges. Either the tier is trusted with dispatchers or
# it is not; a line drawn between two equally destructive verbs is not a line.
# tests/eval_llm.py measures that trust on read/write pairs for each of them.
#
# The list decides two things at once. It is how far a wrong classifier answer
# can travel -- these names never reach it -- and it is a verdict the parser can
# state on its own. Those are the same fact said twice: a name that settles the
# question needs no second opinion, and answering "I do not know this command"
# about `python3` was never true.
KNOWN_EXECUTORS = {
    "rm", "rmdir", "unlink", "shred", "dd", "mkfs", "mkswap", "wipefs",
    "fdisk", "parted", "sgdisk", "truncate", "tee", "install",
    "mv", "cp", "ln", "chmod", "chown", "chgrp", "touch", "mkdir",
    "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff",
    "mount", "umount", "swapoff", "swapon",
    "useradd", "userdel", "usermod", "groupadd", "passwd", "chpasswd",
    "visudo", "sudo", "su", "doas", "pkexec", "setcap", "setfacl",
    "sh", "bash", "zsh", "dash", "ksh", "fish", "eval", "exec", "source",
    "python", "python3", "perl", "ruby", "node", "php", "xargs",
    "crontab", "at", "modprobe", "insmod", "rmmod",
}

# mkfs and fsck ship one binary per filesystem -- mkfs.ext4, fsck.xfs -- so the
# names above only cover the dispatchers.
KNOWN_EXECUTOR_PREFIXES = ("mkfs.", "fsck.", "mount.", "umount.")

SUBST_PLACEHOLDER = "\x00SUBST\x00"

# Command names accepted while validating the current line, for the
# cross-command checks in check_whole_line(). Reset by is_read_only().
SEEN_COMMANDS = []

# The one `cd` target of the current line, or None when the parser cannot name
# it (no operand, `cd -`, a variable, a glob). None is not "no target" -- it is
# "this line moves somewhere I cannot inspect", which check_whole_line() has to
# refuse rather than skip. Reset alongside SEEN_COMMANDS.
SEEN_CD_TARGETS = []

# git subcommands seen on the current line, so check_whole_line() can tell a
# verb that reads the remote configuration from one that does not.
SEEN_GIT_SUBCOMMANDS = []


class Deny(Exception):
    """A rejection, split into the rule that fired and the value that tripped it.

    Callers pass the format template and its arguments separately -- `Deny("find
    %s", flag)` rather than `Deny("find %s" % flag)` -- so the constant half can
    be recovered. Without that split the denial log cannot be grouped: every
    rejected filename produces its own "output redirection to 'a.txt'" bucket,
    and the one question the log exists to answer -- which rule fires most --
    becomes unanswerable.
    """

    def __init__(self, template, *args):
        Exception.__init__(self, template % args if args else template)
        self.rule = template.replace("%s", "").replace("%r", "")
        self.rule = " ".join(self.rule.split()).rstrip(":,- ")
        self.detail = " ".join(str(a) for a in args) if args else None


# ---------------------------------------------------------------- scanning

def find_matching_paren(cmd, open_idx):
    """Index of the `)` matching the `(` at open_idx, quote- and nest-aware."""
    depth = 0
    i = open_idx
    n = len(cmd)
    in_sq = in_dq = False
    while i < n:
        c = cmd[i]
        if in_sq:
            if c == "'":
                in_sq = False
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if in_dq:
            if c == '"':
                in_dq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
        elif c == '"':
            in_dq = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise Deny("unbalanced parenthesis")


def read_braced(cmd, i):
    """Consume a ${...} expansion starting at i. Returns (text, next_index)."""
    if cmd.startswith("${!", i):
        raise Deny("indirect variable expansion")
    depth = 0
    j = i + 1
    n = len(cmd)
    while j < n:
        if cmd[j] == "{":
            depth += 1
        elif cmd[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    if j >= n:
        raise Deny("unterminated parameter expansion")
    text = cmd[i:j + 1]
    if "$(" in text or "`" in text:
        raise Deny("substitution inside parameter expansion")
    return text, j + 1


# ---------------------------------------------------------------- tokenizer

OPERATORS = (";;", "&&", "||", ";", "|", "&", "(", ")", "\n")


def tokenize(cmd, depth):
    """Quote-aware split into WORD / OP tokens.

    `$(...)` is validated recursively and collapsed to a placeholder inside the
    surrounding word, so quoting and word boundaries survive intact. Output
    redirection is consumed here and only allowed to /dev/null-style targets.
    """
    tokens = []
    buf = []
    i = 0
    n = len(cmd)
    in_dq = False

    def flush():
        if buf:
            tokens.append(("WORD", "".join(buf)))
            del buf[:]

    while i < n:
        c = cmd[i]

        if in_dq:
            if c == "\\":
                buf.append(cmd[i:i + 2])
                i += 2
                continue
            if c == '"':
                in_dq = False
                buf.append(c)
                i += 1
                continue
            if c == "`":
                raise Deny("backtick substitution")
            if cmd.startswith("$((", i):
                j = cmd.find("))", i)
                if j < 0:
                    raise Deny("unterminated arithmetic expansion")
                buf.append(cmd[i:j + 2])
                i = j + 2
                continue
            if cmd.startswith("$(", i):
                close = find_matching_paren(cmd, i + 1)
                validate_line(cmd[i + 2:close], depth + 1)
                buf.append(SUBST_PLACEHOLDER)
                i = close + 1
                continue
            if cmd.startswith("${", i):
                text, i = read_braced(cmd, i)
                buf.append(text)
                continue
            buf.append(c)
            i += 1
            continue

        if c == "\\":
            buf.append(cmd[i:i + 2])
            i += 2
            continue

        if c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                raise Deny("unterminated single quote")
            buf.append(cmd[i:j + 1])
            i = j + 1
            continue

        if c == '"':
            in_dq = True
            buf.append(c)
            i += 1
            continue

        if c == "`":
            raise Deny("backtick substitution")

        if cmd.startswith("$((", i):
            j = cmd.find("))", i)
            if j < 0:
                raise Deny("unterminated arithmetic expansion")
            buf.append(cmd[i:j + 2])
            i = j + 2
            continue

        if cmd.startswith("${", i):
            text, i = read_braced(cmd, i)
            buf.append(text)
            continue

        if cmd.startswith("$(", i):
            close = find_matching_paren(cmd, i + 1)
            validate_line(cmd[i + 2:close], depth + 1)
            buf.append(SUBST_PLACEHOLDER)
            i = close + 1
            continue

        if cmd.startswith("<(", i) or cmd.startswith(">(", i):
            raise Deny("process substitution")

        if cmd.startswith("<<", i):
            # Allowed only for a line already redirecting into the scratchpad,
            # and only with a quoted delimiter: an unquoted one expands
            # `$(...)` in the body, which makes the body code rather than data.
            # Consuming it drops the body from the token stream, so what is
            # left still has to clear every other rule -- `bash <<'EOF'` keeps
            # failing on `bash`. Every command that would execute the body is a
            # KNOWN_EXECUTOR, so the body only ever reaches a reader.
            #
            # `cat <<'EOF' > <scratch>/h.py` -- heredoc before the redirect --
            # is not recognised and still prompts. Conservative on purpose: the
            # flag cannot be set by a redirect the tokenizer has not reached.
            i = consume_heredoc(cmd, i)
            continue

        if c == "<":
            flush()
            i += 1
            continue

        if c == ">":
            i = consume_output_redirect(cmd, i, buf, tokens)
            continue

        # Newlines separate commands. This must be checked before the generic
        # whitespace branch below, or `ls\nrm -rf x` collapses into a single
        # segment and `rm` gets read as an argument of `ls`.
        if c in "\n\r":
            flush()
            tokens.append(("OP", "\n"))
            i += 1
            continue

        if c.isspace():
            flush()
            i += 1
            continue

        matched = None
        for op in OPERATORS:
            if cmd.startswith(op, i):
                matched = op
                break
        if matched:
            flush()
            tokens.append(("OP", matched))
            i += len(matched)
            continue

        buf.append(c)
        i += 1

    if in_dq:
        raise Deny("unterminated double quote")
    flush()
    return tokens


def consume_heredoc(cmd, i):
    """Skip a quoted heredoc body writing into the scratchpad. Else raise Deny.

    Returns the index just past the terminator line. The body is never parsed:
    it is the file being written, not a command, and the gate in the caller
    guarantees the only thing reading it is an allowlisted reader.
    """
    n = len(cmd)
    j = i + 2
    if j < n and cmd[j] == "-":     # <<- strips leading tabs from the terminator
        j += 1
    while j < n and cmd[j] in " \t":
        j += 1
    if not SCRATCH_REDIRECT or j >= n or cmd[j] not in "'\"":
        raise Deny("heredoc")
    quote = cmd[j]
    close = cmd.find(quote, j + 1)
    if close < 0:
        raise Deny("unterminated heredoc")
    delim = cmd[j + 1:close]
    if not delim:
        raise Deny("heredoc")
    pos = cmd.find("\n", close)
    if pos < 0:
        raise Deny("unterminated heredoc")
    pos += 1
    while True:
        eol = cmd.find("\n", pos)
        line = cmd[pos:eol if eol >= 0 else n]
        if line.strip() == delim:
            return eol + 1 if eol >= 0 else n
        if eol < 0:
            raise Deny("unterminated heredoc")
        pos = eol + 1


def consume_output_redirect(cmd, i, buf, tokens):
    """Handle `>`/`>>` at position i. Returns the new index, or raises Deny."""
    pending = "".join(buf)
    if pending and (pending.isdigit() or pending == "&"):
        del buf[:]
    elif pending:
        tokens.append(("WORD", pending))
        del buf[:]

    n = len(cmd)
    i += 1
    if i < n and cmd[i] == ">":
        i += 1
    if i < n and cmd[i] == "&":
        i += 1
        j = i
        while j < n and (cmd[j].isdigit() or cmd[j] == "-"):
            j += 1
        if j == i:
            raise Deny("ambiguous fd duplication")
        return j

    while i < n and cmd[i] in " \t":
        i += 1
    j = i
    while j < n and not cmd[j].isspace() and cmd[j] not in ";|&()":
        j += 1
    target = cmd[i:j].strip("\"'")
    if target not in REDIR_OK_TARGETS:
        if is_scratch_path(target):
            SCRATCH_REDIRECT.append(target)
            return j
        raise Deny("output redirection to %r", target)
    return j


# ---------------------------------------------------------------- validation

def is_assignment(word):
    if "=" not in word:
        return False
    name = word.split("=", 1)[0]
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in name)


def unquote(word):
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'":
        return word[1:-1]
    return word


def check_assignment(word):
    """Refuse a `VAR=value` prefix unless VAR only affects locale or formatting.

    Shared by the two places an assignment can precede a command -- bare
    `VAR=value cmd` and `env VAR=value cmd`. They must agree: the whole point of
    the restriction is that variables like PAGER and GIT_EXTERNAL_DIFF name a
    program the command will execute, and `env` in front changes nothing about
    that.
    """
    name = word.split("=", 1)[0]
    if name not in ENV_PREFIX_OK and not name.startswith("LC_"):
        raise Deny("%s= prefixes a command", name)


def check_find(args):
    for a in args:
        if a in FIND_BAD or a.startswith("-fprint"):
            raise Deny("find %s", a)


def walk_flags(args, exact_ok, with_value, cmd, value_hook=None,
               scan_all=False):
    """Return the operands, refusing any flag that is not on the allowlist.

    Short flags bundle (`sort -rn`) and carry their value attached (`awk -F:`),
    so they are walked one character at a time rather than matched whole.
    Bundling is why the allowlist has to be consulted per letter: `-bi` must not
    be accepted just because neither `-b` nor `-i` is spelled out anywhere.

    `value_hook` maps a flag to a function that inspects its value, for the ones
    that carry something worth reading -- awk's `-e` takes a program.

    `scan_all` keeps walking past the operands instead of handing them back at
    the first one. Some tools go on taking flags after their operand and mean
    them: `curl URL -o f` writes the file, `unzip x.zip -d /tmp` extracts, and
    `javap Foo -J...` reaches the JVM. Stopping at the first operand reads all
    three as harmless.
    """
    operands = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            if not scan_all:
                return args[i + 1:]
            i += 1
            continue
        if not a.startswith("-") or a == "-":
            if not scan_all:
                return args[i:]
            operands.append(a)
            i += 1
            continue

        if a.startswith("--"):
            head, sep, value = a.partition("=")
            if head in with_value:
                if not sep:
                    i += 1
                    if i >= len(args):
                        raise Deny(cmd + " %s without a value", head)
                    value = args[i]
            elif head in exact_ok:
                i += 1
                continue
            else:
                raise Deny(cmd + " %s", head)
            if value_hook and head in value_hook:
                value_hook[head](value)
            i += 1
            continue

        # A short flag that carries an optional attached value can be spelled
        # out whole (date's -Iseconds); bundles like -rn fall through to the
        # per-character walk below.
        if a in exact_ok:
            i += 1
            continue

        j = 1
        while j < len(a):
            flag = "-" + a[j]
            if flag in with_value:
                value = a[j + 1:]
                if not value:
                    i += 1
                    if i >= len(args):
                        raise Deny(cmd + " %s without a value", flag)
                    value = args[i]
                if value_hook and flag in value_hook:
                    value_hook[flag](value)
                break  # the rest of the word was the value
            if flag not in exact_ok:
                raise Deny(cmd + " %s", flag)
            j += 1
        i += 1
    return operands


def check_sort(args):
    walk_flags(args, SORT_FLAGS_OK, SORT_FLAGS_WITH_VALUE, "sort")


def check_date(args):
    for operand in walk_flags(args, DATE_FLAGS_OK, DATE_FLAGS_WITH_VALUE,
                              "date"):
        if not operand.startswith("+"):
            raise Deny("date sets the clock from %r", operand)


def check_awk_program(text):
    blob = unquote(text).lower()
    for bad in AWK_BAD:
        if bad in blob:
            raise Deny("awk program contains %r", bad)
    i = 0
    while i < len(blob):
        if blob[i] == ">":
            if i + 1 < len(blob) and blob[i + 1] == "=":
                i += 2
                continue
            raise Deny("awk program contains a redirection")
        i += 1


def check_awk(args):
    """Screen awk's flags, then its program text.

    The flags have to come first. Screening the program was never enough on its
    own: `-f prog.awk` takes the program from a file this parser cannot see, and
    gawk's -o, -p and -d each write one, while -l loads a shared object. None of
    those appear in AWK_FLAGS_OK, which is now the whole of why they are
    refused.
    """
    from_flag = []

    def screen(program):
        from_flag.append(program)
        check_awk_program(program)

    operands = walk_flags(args, AWK_FLAGS_OK,
                          AWK_FLAGS_WITH_VALUE | AWK_PROGRAM_FLAGS, "awk",
                          dict.fromkeys(AWK_PROGRAM_FLAGS, screen))
    # With -e the program came from the flag, so the first operand is a file.
    if operands and not from_flag:
        check_awk_program(operands[0])


def check_sed(args):
    script_seen = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression", "-f", "--file"):
            if a in ("-f", "--file"):
                raise Deny("sed script file")
            i += 1
            if i >= len(args):
                raise Deny("sed -e without a script")
            check_sed_script(unquote(args[i]))
            script_seen = True
            i += 1
            continue
        if a.startswith("--expression="):
            check_sed_script(unquote(a.split("=", 1)[1]))
            script_seen = True
            i += 1
            continue
        if a.startswith("-"):
            if a in SED_FLAGS_OK:
                i += 1
                continue
            raise Deny("sed flag %s", a)
        if not script_seen:
            check_sed_script(unquote(a))
            script_seen = True
        i += 1
    if not script_seen:
        raise Deny("sed without a recognized script")


def check_sed_script(script):
    import re
    for pattern in SED_SAFE_PATTERNS:
        if re.match(pattern, script):
            return
    raise Deny("sed script not in the recognized read-only set: %r", script)


def check_fd(args):
    for a in args:
        if a in FD_BAD or a.startswith("--exec"):
            raise Deny("fd %s", a)


def check_tree(args):
    for a in args:
        if a == "-o" or a.startswith("--output"):
            raise Deny("tree writes to a file")


def strip_quoted(word):
    """Drop quoted spans so glob characters can be spotted outside quotes."""
    out = []
    i = 0
    n = len(word)
    while i < n:
        c = word[i]
        if c == "\\":
            i += 2
            continue
        if c in "'\"":
            j = i + 1
            while j < n and word[j] != c:
                if word[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def has_unquoted_glob(word):
    bare = strip_quoted(word)
    return any(ch in bare for ch in "*?[")


def check_glob_sensitive(cmd, args):
    for a in args:
        if has_unquoted_glob(a):
            raise Deny("unquoted glob next to %s can expand to a flag", cmd)


def check_rg(args):
    for a in args:
        if a in RG_BAD_FLAGS or any(
            a.startswith(f + "=") for f in RG_BAD_FLAGS if f.startswith("--")
        ):
            raise Deny("rg %s", a)


def check_file(args):
    walk_flags(args, FILE_FLAGS_OK, FILE_FLAGS_WITH_VALUE, "file")


def check_javap(args):
    """Disassembly is a read; the flags that reach the JVM are not.

    `-cp` and friends are pulled out with their value first. Left in, the
    per-letter walk reads `-cp` as the bundle `-c -p` and the classpath that
    follows becomes an operand, so a flag that takes a path would look like a
    class name.
    """
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in JAVAP_FLAGS_TAKING_NEXT:
            i += 1
            if i >= len(args):
                raise Deny("javap %s without a value", a)
            i += 1
            continue
        rest.append(a)
        i += 1
    walk_flags(rest, JAVAP_FLAGS_OK, JAVAP_FLAGS_WITH_VALUE, "javap",
               scan_all=True)


def check_unzip(args):
    """Refuse unless a listing flag is present: extraction is the default.

    Two passes for two questions. The first asks whether anything on the line
    puts unzip into a mode that does not write, and it has to see through
    bundles (`-lq`). The second is the ordinary flag allowlist, which is what
    catches `-d` wherever it sits -- including after the archive name, where it
    still picks the extraction directory.
    """
    listed = False
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and not a.startswith("--") and a != "-":
            j = 1
            while j < len(a):
                flag = "-" + a[j]
                if flag in UNZIP_FLAGS_WITH_VALUE:
                    if not a[j + 1:]:
                        i += 1  # its value is the next word
                    break
                if flag in UNZIP_LIST_FLAGS:
                    listed = True
                j += 1
        i += 1
    if not listed:
        raise Deny("unzip without a list flag extracts")
    walk_flags(args, UNZIP_FLAGS_OK, UNZIP_FLAGS_WITH_VALUE, "unzip",
               scan_all=True)


def check_curl(args):
    walk_flags(args, CURL_FLAGS_OK, CURL_FLAGS_WITH_VALUE, "curl",
               scan_all=True)


def check_jq(args):
    for a in args:
        if a in JQ_BAD_FLAGS:
            raise Deny("jq %s", a)
        for flag in JQ_BAD_FLAGS:
            if flag.startswith("--") and a.startswith(flag + "="):
                raise Deny("jq %s", a)
        if a.startswith("-") and not a.startswith("--") and (
            "f" in a[1:] or "L" in a[1:]
        ):
            raise Deny("jq %s", a)
    program = " ".join(unquote(a) for a in args if not a.startswith("-"))
    for bad in JQ_BAD_PROGRAM:
        if bad in program:
            raise Deny("jq program contains %r", bad)


def check_gh_api(args):
    method = None
    has_field = False
    endpoint = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-X", "--method"):
            i += 1
            if i >= len(args):
                raise Deny("gh api --method without a value")
            method = unquote(args[i]).upper()
        elif a.startswith("--method="):
            method = unquote(a.split("=", 1)[1]).upper()
        elif a in ("--input",) or a.startswith("--input="):
            raise Deny("gh api --input sends a request body")
        elif a in GH_API_FIELD_FLAGS:
            has_field = True
            i += 1  # its value
        elif any(a.startswith(f + "=") for f in GH_API_FIELD_FLAGS
                 if f.startswith("--")):
            has_field = True
        elif a in GH_API_VALUE_FLAGS:
            i += 1  # its value, so it is not mistaken for the endpoint
        elif not a.startswith("-") and endpoint is None:
            endpoint = unquote(a)
        i += 1

    if method is not None and method not in ("GET", "HEAD"):
        raise Deny("gh api -X %s", method)
    if has_field and method not in ("GET", "HEAD"):
        raise Deny("gh api request fields switch the method to POST")
    if endpoint and endpoint.lower() == "graphql":
        raise Deny("gh api graphql")


def check_gh(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-R", "--repo"):
            i += 2
            continue
        i += 1
    if i >= len(args):
        return  # bare `gh` prints help

    sub = unquote(args[i])
    rest = args[i + 1:]
    if sub == "api":
        return check_gh_api(rest)
    if sub not in GH_READ_SUBCOMMANDS:
        act = next((unquote(a) for a in rest if not a.startswith("-")), None)
        if act in GH_WRITE_ACTIONS.get(sub, ()):
            raise Deny("known write/exec gh subcommand: %s %s", sub, act)
        raise Deny("gh %s", sub)

    allowed = GH_READ_SUBCOMMANDS[sub]
    if not allowed:
        return  # `gh status`, `gh version`
    action = next((unquote(a) for a in rest if not a.startswith("-")), None)
    if action not in allowed:
        if action in GH_WRITE_ACTIONS.get(sub, ()):
            raise Deny("known write/exec gh subcommand: %s %s", sub, action)
        raise Deny("gh %s %s", sub, action)


def cd_target(args):
    """The one directory a `cd` moves to, or None when it cannot be named.

    None covers `cd` with no operand (home), `cd -` (the previous directory),
    a variable, and a glob. All four leave the destination outside what this
    parser can read, which is a different thing from there being no
    destination -- see check_whole_line().
    """
    words = [a for a in args if not a.startswith("-")]
    if len(words) != 1:
        return None
    word = words[0]
    if has_unquoted_glob(word):
        return None
    target = unquote(word)
    if SUBST_PLACEHOLDER in target or "$" in target:
        return None
    return target


def check_uniq(args):
    operands = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            if a in ("-f", "-s", "-w", "--skip-fields", "--skip-chars",
                     "--check-chars", "--all-repeated", "--group"):
                skip_next = a in ("-f", "-s", "-w")
            continue
        operands.append(a)
    if len(operands) > 1:
        raise Deny("uniq second operand is an output file")


def check_git(args):
    for a in args:
        # --output=<file> writes; -c can set core.pager/alias to a shell command.
        if a.startswith("--output") or a == "-o":
            raise Deny("git writes to a file")
        if a.startswith("--open-files-in-pager") or a == "-O":
            raise Deny("git pager command")
        if a.startswith("--exec-path") or a.startswith("--upload-pack"):
            raise Deny("git exec path override")

    idx = 0
    while idx < len(args):
        a = args[idx]
        if a == "-c":
            raise Deny("git -c can set core.pager to a shell command")
        if a in GIT_FLAGS_WITH_VALUE:
            idx += 2
            continue
        if a.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(args):
        return  # bare `git` prints usage
    sub = args[idx]
    rest = args[idx + 1:]
    # Recorded before the membership test so check_whole_line() sees the verb of
    # every git on the line, `-C <path>` forms included.
    SEEN_GIT_SUBCOMMANDS.append(unquote(sub))
    if sub not in GIT_READ_SUBCOMMANDS:
        if unquote(sub) in GIT_WRITE_SUBCOMMANDS:
            raise Deny("known write/exec git subcommand: %s", unquote(sub))
        raise Deny("git %s", sub)

    if sub == "config":
        if not any(r.startswith(("--get", "--list", "-l")) for r in rest):
            raise Deny("git config write")
    elif sub == "branch":
        # Listing forms only: any bare operand creates/renames a branch.
        for r in rest:
            if not r.startswith("-"):
                raise Deny("git branch operand")
            if r in GIT_BRANCH_MUTATE or r.startswith("--set-upstream"):
                raise Deny("git branch %s", r)
    elif sub == "remote":
        action = next((r for r in rest if not r.startswith("-")), None)
        if action is not None and action not in ("show", "get-url"):
            raise Deny("git remote %s", action)
    elif sub == "reflog":
        action = next((r for r in rest if not r.startswith("-")), None)
        if action is not None and action != "show":
            raise Deny("git reflog %s", action)
    elif sub == "worktree":
        # `list` only. Every other action on this subcommand -- and the bare
        # form, which prints usage -- creates, moves or deletes a working tree.
        action = next((r for r in rest if not r.startswith("-")), None)
        if action != "list":
            raise Deny("git worktree %s", action)


CHECKERS = {
    "find": check_find,
    "sort": check_sort,
    "date": check_date,
    "awk": check_awk,
    "gawk": check_awk,
    "mawk": check_awk,
    "sed": check_sed,
    "git": check_git,
    "fd": check_fd,
    "fdfind": check_fd,
    "tree": check_tree,
    "uniq": check_uniq,
    "jq": check_jq,
    "rg": check_rg,
    "file": check_file,
    "gh": check_gh,
    "javap": check_javap,
    "unzip": check_unzip,
    "curl": check_curl,
}


def validate_command(words, depth=0):
    """Validate one simple command (a list of WORD strings)."""
    if depth > 6:
        raise Deny("nesting too deep")

    idx = 0
    while idx < len(words) and is_assignment(words[idx]):
        idx += 1
    assignments = words[:idx]
    words = words[idx:]
    if not words:
        return  # assignment-only segment: sets a shell variable, runs nothing

    # Assignments that prefix a command run that command with the variable set.
    for a in assignments:
        check_assignment(a)

    cmd = unquote(words[0])
    args = words[1:]

    if cmd in SHELL_KEYWORDS_SKIP or cmd in SHELL_KEYWORDS_STRIP:
        if args:
            return validate_command(args, depth + 1)
        return
    if cmd in SHELL_KEYWORDS_WORDLIST:
        return  # `for x in ...`, `case x in` -- word lists, not commands

    if SUBST_PLACEHOLDER in cmd or cmd.startswith("$"):
        raise Deny("indirect command")
    if "/" in cmd:
        if not (cmd.startswith("/usr/bin/") or cmd.startswith("/bin/")):
            raise Deny("path-qualified command %r", cmd)
        # The prefix only means anything if the path stays under it. Without
        # this, `/bin/../tmp/ls` is checked as `ls` and runs `/tmp/ls`.
        if ".." in cmd.split("/"):
            raise Deny("path-qualified command %r", cmd)
        cmd = cmd.rsplit("/", 1)[1]

    if cmd in WRAPPERS:
        rest = list(args)
        if cmd == "env":
            while rest:
                word = rest[0]
                if is_assignment(word):
                    check_assignment(word)
                elif word in ENV_FLAGS_WITH_VALUE:
                    rest = rest[1:]  # the value is data, not a command
                elif word in ENV_FLAGS_OK or word.startswith("--unset="):
                    pass
                elif word.startswith("-u") and len(word) > 2:
                    pass  # -uNAME, the attached form of --unset
                elif word.startswith("-"):
                    raise Deny("env %s", word)
                else:
                    break  # first non-option word: the command being wrapped
                rest = rest[1:]
            # Reaching the end without a command means every word was an option
            # or an assignment, so this run only prints the environment. That is
            # read-only -- but only because each word above was recognized. The
            # earlier version drew the same conclusion from an empty list it had
            # emptied by discarding unrecognized flags, which is how `env -S`
            # passed as if it were a bare `env`.
            if not rest:
                return
            return validate_command(rest, depth + 1)
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if cmd == "timeout" and rest:
            rest = rest[1:]  # duration argument
        if not rest:
            raise Deny("%s without a command", cmd)
        return validate_command(rest, depth + 1)

    if cmd in GLOB_SENSITIVE:
        check_glob_sensitive(cmd, args)

    if cmd in CHECKERS:
        SEEN_COMMANDS.append(cmd)
        CHECKERS[cmd](args)
        return

    if cmd in ALWAYS_OK:
        if cmd in ("cd", "pushd"):
            SEEN_CD_TARGETS.append(cd_target(args))
        SEEN_COMMANDS.append(cmd)
        return

    if cmd in KNOWN_EXECUTORS or cmd.startswith(KNOWN_EXECUTOR_PREFIXES):
        raise Deny("known write/exec command: %r", cmd)
    raise Deny("command not on read-only allowlist: %r", cmd)


SEPARATORS = {";", ";;", "&&", "||", "|", "&", "(", ")", "\n"}


def validate_line(command, depth=0):
    """Tokenize and validate a full command line. Raises Deny on refusal."""
    if depth > 6:
        raise Deny("substitution nesting too deep")
    tokens = tokenize(command, depth)
    segment = []
    for kind, value in tokens:
        if kind == "OP" and value in SEPARATORS:
            if segment:
                validate_command(segment)
            segment = []
        else:
            segment.append(value)
    if segment:
        validate_command(segment)


def inspect_repo(target):
    """Refuse unless the repository at `target` is inert for a read-only verb.

    Two things are read: the configuration git will consult, and the one hook a
    read-only verb can fire. The unit of the configuration check is the section
    rather than the key, because git only reads its own namespace -- a repo's
    local config always carries keys some other tool wrote (`lfs.*`,
    `branch.<n>.vscode-merge-base`), and treating an unknown key as a dangerous
    one refuses every real repository. See docs/adr/0002.

    Fail closed throughout. A directory that is gone, a path that is not a
    repository, a git that times out: each means the inspection did not happen,
    and an inspection that did not happen is not a clean bill of health.
    """
    import os
    import subprocess

    def git(*argv):
        try:
            proc = subprocess.run(("git", "-C", target) + argv,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,
                                  timeout=GIT_INSPECT_TIMEOUT)
        except Exception:
            proc = None
        if proc is None or proc.returncode != 0:
            raise Deny("cd before git: target repo unreadable: %r", target)
        return proc.stdout.decode("utf-8", "replace").splitlines()

    if not os.path.isdir(target):
        raise Deny("cd before git: target repo unreadable: %r", target)

    entries = git("config", "--local", "--list")

    dirs = git("rev-parse", "--absolute-git-dir", "--git-common-dir")
    if len(dirs) < 2:
        raise Deny("cd before git: target repo unreadable: %r", target)
    git_dir, common_dir = dirs[0], dirs[1]
    if not os.path.isabs(common_dir):
        common_dir = os.path.join(target, common_dir)

    # The worktree-scoped file is read only when the repository turns the
    # extension on, and `git config --worktree --list` is a fatal error on both
    # counts it is not: without the extension in a linked worktree, and with
    # the extension when the file does not exist yet. Neither is an inspection
    # that failed -- there is nothing at that scope to inspect -- so the two
    # preconditions are checked here rather than read out of an exit code that
    # cannot tell them apart from a repository we genuinely cannot read.
    if any(entry.partition("=")[0].strip().lower() == "extensions.worktreeconfig"
           and entry.partition("=")[2].strip().lower() in GIT_CONFIG_TRUE
           for entry in entries) and os.path.isfile(
               os.path.join(git_dir, "config.worktree")):
        entries = entries + git("config", "--worktree", "--list")

    for entry in entries:
        key = entry.split("=", 1)[0].strip().lower()
        if not key:
            continue
        if key.split(".", 1)[0] not in GIT_CONFIG_SECTIONS_READ:
            continue  # git never reads the value, so it cannot run it
        if key not in GIT_CONFIG_KEYS_OK:
            raise Deny("cd before git: config key %r is not harmless", key)

    # The only hook a read-only verb was measured to fire: `git status`
    # refreshes the stat cache and writes the index. Refusing every executable
    # hook was the earlier draft and it disqualified every git-lfs repository
    # while closing nothing a read verb could reach. See docs/adr/0002.
    hook = os.path.join(common_dir, "hooks", "post-index-change")
    if os.path.isfile(hook) and os.access(hook, os.X_OK):
        raise Deny("cd before git: executable post-index-change hook")


def check_whole_line(cwd=None):
    """Cross-command rules that only make sense once the line is fully parsed.

    More than one `cd` makes the effective working directory hard to reason
    about, and that stays a refusal outright. `cd` before `git` was one too,
    and it was the second largest bucket in the log while every sampled line
    was a read. The threat behind it is real -- git runs hooks and reads
    configuration from wherever it lands -- so it is now confirmed instead of
    assumed: the verb must be one that never reads the remote configuration,
    the target must be nameable, and the repository there must inspect clean.
    """
    cds = SEEN_COMMANDS.count("cd") + SEEN_COMMANDS.count("pushd")
    if cds > 1:
        raise Deny("multiple directory changes in one command")
    if not (cds and "git" in SEEN_COMMANDS):
        return

    for sub in SEEN_GIT_SUBCOMMANDS:
        if sub in GIT_NETWORK_SUBCOMMANDS:
            raise Deny("cd before git: network-touching git verb %r", sub)

    if len(SEEN_CD_TARGETS) != 1 or SEEN_CD_TARGETS[0] is None:
        raise Deny("cd before git: cd target not identifiable")

    import os

    target = os.path.expanduser(SEEN_CD_TARGETS[0])
    if not os.path.isabs(target):
        if not (isinstance(cwd, str) and cwd):
            raise Deny("cd before git: cd target not identifiable")
        target = os.path.join(cwd, target)
    inspect_repo(target)


def explain(command, extra_allowed=None, cwd=None):
    """None when the whole line is read-only, otherwise why it was rejected.

    `extra_allowed` adds one command name to the allowlist for this call only.
    It exists so a name the LLM classifier vouched for can be re-checked against
    every other rule rather than bypassing them.

    `cwd` is where the command would run, and only the `cd` before `git` check
    reads it: a relative target has no meaning without it, and a target with no
    meaning is refused.

    The reason is what makes the denial log worth keeping: it turns "this
    prompted" into "this prompted because `sed -i` writes in place", which is
    the difference between a log you can triage and a pile of shell lines.
    """
    if not command or not command.strip():
        return {"rule": "empty command", "detail": None,
                "reason": "empty command"}
    del SCRATCH_REDIRECT[:]
    del SEEN_COMMANDS[:]
    del SEEN_CD_TARGETS[:]
    del SEEN_GIT_SUBCOMMANDS[:]
    added = extra_allowed and extra_allowed not in ALWAYS_OK
    if added:
        ALWAYS_OK.add(extra_allowed)
    try:
        validate_line(command)
        check_whole_line(cwd)
        return None
    except Deny as exc:
        return {"rule": exc.rule or "denied", "detail": exc.detail,
                "reason": str(exc) or "denied"}
    except RecursionError:
        return {"rule": "nesting too deep", "detail": None,
                "reason": "nesting too deep"}
    except Exception as exc:
        name = type(exc).__name__
        return {"rule": "parse error", "detail": name,
                "reason": "parse error: %s" % name}
    finally:
        if added:
            ALWAYS_OK.discard(extra_allowed)


def is_read_only(command):
    return explain(command) is None


# ------------------------------------------------------- LLM second opinion

# The one denial that means "I have never heard of this command" rather than "I
# know this shape and it writes". Only that one is worth a second opinion: the
# others are the structural rules -- redirection, backticks, indirect execution
# -- and those are the parser's whole job.
UNKNOWN_COMMAND_RULE = "command not on read-only allowlist"

LLM_ENV = "PLAN_MODE_AUTOALLOW_LLM"
LLM_ON = {"1", "on", "yes", "true"}

LLM_TIMEOUT = 30
LLM_MODEL = "haiku"

LLM_PROMPT = """\
You are a permission classifier for a coding agent that is in planning mode. \
Decide whether running this shell command line would be READ-ONLY.

READ-ONLY means: it creates, modifies, deletes and renames nothing -- no file, \
no process, no service, no remote resource, no configuration, no package. \
Printing to stdout is read-only. Reading files is read-only. Querying a remote \
API is read-only only if the request cannot change server state.

Treat as NOT read-only: anything that writes or deletes, starts or stops \
anything, installs or upgrades, sends a mutating request, or runs a program \
whose behaviour you cannot see from the line itself.

Judge the line on its own. Do not assume it is safe because it looks routine, \
and do not assume an unfamiliar command is harmless. If you are not certain, \
answer NO.

Command line:
%s

Reply with exactly one word, YES or NO."""


def llm_enabled():
    import os

    return os.environ.get(LLM_ENV, "").strip().lower() in LLM_ON


def cached_allow(command):
    """True when the classifier has already passed this exact command line.

    The cache is the record: an entry means a verdict was reached and stands
    until someone deletes the line. That is the point of keying on the exact
    string -- the same line gets the same answer today and next month, instead
    of a fresh roll of the dice each time it appears.

    `bytes` and `head` narrow the search; the body decides it. A body that has
    been collected is a miss, and asking again is the right answer: the
    judgment line alone no longer proves which command line it stood for.
    """
    import os

    path = log_path()
    if not path:
        return False
    blob = command.encode("utf-8")
    head = command.split("\n", 1)[0][:HEAD_LEN]
    directory = bodies_dir(path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("rule") != CLASSIFIER_ALLOW_RULE:
                    continue
                if record.get("bytes") != len(blob) or record.get("head") != head:
                    continue
                ref = record.get("ref")
                if not ref:
                    continue
                try:
                    with open(os.path.join(directory, ref), "rb") as body:
                        if body.read() == blob:
                            return True
                except (IOError, OSError):
                    continue
    except (IOError, OSError):
        pass
    return False


def record_allow(command, name, cwd=None):
    """Record a classifier pass as one more judgment, keyed by command name."""
    record_judgment(command, CLASSIFIER_ALLOW_RULE, name, cwd)


def llm_says_read_only(command):
    """Ask `claude -p`. Anything other than a clear YES is a no.

    Every failure -- no binary, no network, timeout, unparseable answer --
    returns False, which leaves the command exactly where it was: at the
    permission prompt. The classifier can only ever remove a prompt, never add
    a way for one to be skipped by accident.
    """
    try:
        import subprocess

        # The prompt goes on stdin, not as an argument: --disallowedTools takes
        # a variadic list, so a trailing prompt is read as one more tool name
        # and the run dies asking for input it was already given.
        proc = subprocess.run(
            ["claude", "-p", "--model", LLM_MODEL, "--max-turns", "1",
             "--output-format", "json",
             "--disallowedTools", "Bash,Read,Write,Edit,Glob,Grep,WebFetch,"
                                  "WebSearch,Task,NotebookEdit"],
            input=(LLM_PROMPT % command).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=LLM_TIMEOUT,
        )
        if proc.returncode != 0:
            return False
        payload = json.loads(proc.stdout.decode("utf-8", "replace"))
        if payload.get("is_error"):
            return False
        return payload.get("result", "").strip().upper().rstrip(".") == "YES"
    except Exception:
        return False


def llm_second_opinion(command, verdict, cwd=None):
    """Re-judge a command the parser refused only because it did not know it.

    A YES does not approve the line by itself. It adds the one name to the
    allowlist and the parser runs again, so a command that clears the classifier
    still has to clear every structural rule -- redirection, backticks, `cd`
    before `git`. The classifier's power is exactly "this name is a reader",
    which is the only question it was asked.
    """
    if not llm_enabled() or verdict["rule"] != UNKNOWN_COMMAND_RULE:
        return False
    name = verdict["detail"]
    # The rule gate above already excludes these -- a known executor gets its
    # own verdict now -- so this is a second lock on the same door. It stays
    # because the cost of it being redundant is nothing and the cost of the
    # gate ever loosening is a model vote on `rm`.
    if not name or name in KNOWN_EXECUTORS:
        return False
    if name.startswith(KNOWN_EXECUTOR_PREFIXES):
        return False
    cached = cached_allow(command)
    if not cached and not llm_says_read_only(command):
        return False
    if explain(command, extra_allowed=name, cwd=cwd) is not None:
        return False
    if not cached:
        record_allow(command, name, cwd)
    return True


# ----------------------------------------------------------- judgment log

# Every command the hook did not auto-allow is appended here, so the allowlist
# can be widened from evidence instead of guesswork. There is one file, not one
# per verdict: the axis the hook already knows (allowed / denied) carries no
# information, and the axis that does -- did the parser prove this writes, or
# admit it does not know -- is computed by replay() at read time. Promote a rule
# and the lines it covers leave the open list on their own.
#
# The log lives in its own directory rather than loose in ~/.claude: the bodies
# are a second entry, and the directory gives the README a place to sit, so
# someone who finds the log without knowing the hook can work out what wrote it
# and how to read it.
LOG_ENV = "PLAN_MODE_AUTOALLOW_LOG"
LOG_DIRNAME = "plan-mode-autoallow"
LOG_BASENAME = "judgments.jsonl"
LOG_OFF = {"", "off", "0", "no", "false", "none"}

# Command lines live beside the judgments rather than inside them. That is what
# lets the judgments file be append-only: a line is ~470 B, so a year of it is
# ~2 MB, while the bodies are where the volume and the sensitivity collect.
BODIES_DIRNAME = "bodies"
BODIES_MAX_BYTES = 2 * 1024 * 1024
HEAD_LEN = 160

# The rule a classifier pass is filed under. It is a judgment like any other,
# and the one whose replay disagreeing means "the parser could be taught this".
CLASSIFIER_ALLOW_RULE = "allowed by classifier"

# Not a verdict about the command: the body was collected, so there is nothing
# to re-judge. Readers that compare verdicts have to set these aside rather than
# count them as a change of mind.
UNREPLAYABLE_RULE = "body unavailable"

# The rules that are admissions rather than proofs. Membership is the whole
# definition of "open command": the parser said it did not know, or could not
# check. Redirection, heredocs, known executors and the rest proved the line
# writes -- they are answered, not open, and re-reading them every cycle is how
# the old log buried the fifteen names that were actually questions.
#
# `git` and `gh` are the coarse two. Their rule constant is what is left after
# the subcommand is stripped out, so it covers both halves of "this subcommand
# is not in the read set" -- `git frobnicate`, which is a question, and `git
# push`, which is not. Separating them would mean enumerating the write
# subcommands of two tools whose surface is exactly what the read set exists to
# avoid enumerating, so the detail column is where that reading happens.
OPEN_RULES = frozenset({
    UNKNOWN_COMMAND_RULE,
    "git",                                        # a git subcommand not read
    "gh",                                         # a gh subcommand not read
    "git branch operand",                         # listing forms it cannot say
    "cd before git: target repo unreadable",      # fail closed, not a proof
    "cd before git: cd target not identifiable",
    "cd before git: network-touching git verb",
})


def log_path():
    """Where to append judgments, or None when logging is switched off."""
    import os

    configured = os.environ.get(LOG_ENV)
    if configured is not None:
        if configured.strip().lower() in LOG_OFF:
            return None
        return os.path.expanduser(configured)
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.join(base, LOG_DIRNAME, LOG_BASENAME)


def bodies_dir(path):
    """Where the command lines for `path` live."""
    import os

    return os.path.join(os.path.dirname(path), BODIES_DIRNAME)


def collect_bodies(directory):
    """Drop the oldest bodies once the directory passes its ceiling.

    Only the bodies are collected. A judgment whose body is gone still replays
    -- as `body unavailable` -- so the count of what was refused survives even
    when the text of it does not.
    """
    import os

    entries = []
    total = 0
    for name in os.listdir(directory):
        try:
            stat = os.stat(os.path.join(directory, name))
        except OSError:
            continue
        entries.append((stat.st_mtime, stat.st_size,
                        os.path.join(directory, name)))
        total += stat.st_size
    if total <= BODIES_MAX_BYTES:
        return
    for _, size, path in sorted(entries):
        if total <= BODIES_MAX_BYTES:
            return
        try:
            os.remove(path)
            total -= size
        except OSError:
            pass


def write_body(command, directory):
    """Store a command line and return the ref that names it.

    Content-addressed, so the same line written twice is one file. That is a
    side effect rather than the point: the point is that the judgment and the
    text it was passed on are separately sized and separately kept.
    """
    import hashlib
    import os

    blob = command.encode("utf-8")
    ref = hashlib.sha256(blob).hexdigest()[:16]
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        fd = os.open(os.path.join(directory, ref),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return ref  # already stored: the content is the name
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    collect_bodies(directory)
    return ref


def record_judgment(command, rule, detail, cwd=None, ts=None):
    """Append one judgment. Never raises -- the decision is already made.

    Imports live in the function body: this runs only when a command was not
    auto-allowed, and the hook's cost is dominated by module import on the path
    that matters (a command that gets allowed).

    `rule` and `detail` are what make the file a dataset rather than a pile of
    sentences -- see report(). There is no `reason`: it was the two of them
    joined, and `head` serves the one thing it was kept for, which is that the
    first way anyone reads this file is `tail`.

    Nothing rotates. The file is a regression suite, and rotation quietly drops
    the oldest test cases two cycles later.
    """
    try:
        import os
        import time

        path = log_path()
        if not path:
            return
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        blob = command.encode("utf-8")
        record = {
            "ts": ts or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "rule": rule,
            "detail": detail,
        }
        if isinstance(cwd, str) and cwd:
            record["cwd"] = cwd
        record["head"] = command.split("\n", 1)[0][:HEAD_LEN]
        record["ref"] = write_body(command, bodies_dir(path))
        record["bytes"] = len(blob)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        # O_APPEND keeps concurrent hook processes from interleaving, and the
        # mode matters because command lines can carry anything the agent typed.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:
        pass


def log_denial(command, verdict, cwd=None):
    """Record a parser refusal."""
    record_judgment(command, verdict["rule"], verdict["detail"], cwd)


def load_judgments(path=None):
    """Judgments with their bodies read back in, oldest first.

    A record whose body has been collected keeps everything but `command`.
    replay() turns that absence into a verdict of its own rather than a guess.
    """
    import os

    path = path or log_path()
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    directory = bodies_dir(path)
    records = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        ref = record.get("ref")
        if ref and "command" not in record:
            try:
                with open(os.path.join(directory, ref), "rb") as body:
                    record["command"] = body.read().decode("utf-8", "replace")
            except (IOError, OSError):
                pass
        records.append(record)
    return records


def load_log(path):
    """Records from a legacy log and its rotated predecessor, oldest first.

    The old format carried the command line inline, which is why migrate() can
    hand these straight to replay() without a special case.
    """
    records = []
    for candidate in (path + ".1", path):
        try:
            with open(candidate, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for line in lines:
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records


def replay(records):
    """Re-judge stored commands with today's parser. The one primitive here.

    --report, --open, --regress and --migrate are all thin callers of it. The
    open list and the aggregates are views computed when someone looks, not
    files that have to be compacted every time a rule is promoted -- and the
    same call is how a parser change is measured against 22 days of real
    command lines without a network round trip or a token.
    """
    verdicts = []
    for record in records:
        command = record.get("command")
        if not isinstance(command, str) or not command:
            verdicts.append({"rule": UNREPLAYABLE_RULE,
                             "detail": record.get("ref"),
                             "reason": UNREPLAYABLE_RULE})
            continue
        verdicts.append(explain(command, cwd=record.get("cwd")))
    return verdicts


def shorten(text, width=80):
    flat = " ".join((text or "").split())
    return flat if len(flat) <= width else flat[:width - 3] + "..."


def report(path=None):
    """Summarise the log as today's parser judges it.

    Grouped by `rule` rather than by the sentence, because a rule that embeds a
    value -- "output redirection to 'a.txt'" -- would otherwise land in a bucket
    of one and never rise to the top of the list, which is the whole reason to
    read this file.

    The counts are replay verdicts, not stored ones. What the parser decided
    last month is history; what it decides now is what a promotion has to move.
    """
    path = path or log_path()
    if not path:
        print("logging is disabled (%s)" % LOG_ENV)
        return 1
    records = load_judgments(path)
    if not records:
        print("%s: no entries" % path)
        return 0
    verdicts = replay(records)

    by_rule = {}
    allowed = missing = open_count = 0
    for verdict in verdicts:
        if verdict is None:
            allowed += 1
            continue
        rule = verdict["rule"]
        if rule == UNREPLAYABLE_RULE:
            missing += 1
        if rule in OPEN_RULES:
            open_count += 1
        counts = by_rule.setdefault(rule, {})
        counts[verdict["detail"]] = counts.get(verdict["detail"], 0) + 1

    print("%s\n%d judgments, %s .. %s\nreplayed: %d auto-allowed, %d refused "
          "in %d rules (%d open, %d body collected)\n"
          % (path, len(records), records[0].get("ts", "?"),
             records[-1].get("ts", "?"), allowed, len(records) - allowed,
             len(by_rule), open_count, missing))
    for rule, details in sorted(by_rule.items(),
                                key=lambda kv: -sum(kv[1].values())):
        top = sorted((d for d in details.items() if d[0]), key=lambda kv: -kv[1])
        shown = "  ".join("%s×%d" % (d, c) for d, c in top[:6])
        if len(top) > 6:
            shown += "  (+%d more)" % (len(top) - 6)
        print("%5d  %s" % (sum(details.values()), rule))
        if shown:
            print("       %s" % shown)

    # What the classifier passed and the parser still cannot express. The name
    # is the aggregation key because the name is what gets added to the parser;
    # a verdict the parser now reaches on its own drops out of this list by
    # replaying clean, which is the point of computing it here.
    candidates = {}
    for record, verdict in zip(records, verdicts):
        if record.get("rule") == CLASSIFIER_ALLOW_RULE and verdict is not None:
            candidates.setdefault(record.get("detail") or "?", []).append(
                record.get("head") or "")
    if candidates:
        print("\n%d commands the classifier passed and the parser cannot "
              "express -- candidates to teach it:\n" % len(candidates))
        for name, heads in sorted(candidates.items(),
                                  key=lambda kv: -len(kv[1])):
            print("%5d  %s" % (len(heads), name))
            for example in sorted(set(heads))[:3]:
                print("       %s" % shorten(example))
            if len(set(heads)) > 3:
                print("       (+%d more)" % (len(set(heads)) - 3))

    print("\nlast %d commands:" % min(10, len(records)))
    for record in records[-10:]:
        print("  %s  %s" % (record.get("ts", "?")[:16],
                            shorten(record.get("head"), 88)))
    return 0


def open_report(path=None):
    """Only the judgments where the parser said it did not know.

    This is the list that decides what to read each cycle. A rule belongs here
    when it is an admission -- an unrecognised name, a repository that could not
    be inspected -- and not when the parser proved the line writes. Nothing is
    deleted to keep it short: promote a rule and its lines fall out on their own.
    """
    path = path or log_path()
    if not path:
        print("logging is disabled (%s)" % LOG_ENV)
        return 1
    records = load_judgments(path)
    verdicts = replay(records)

    buckets = {}
    for record, verdict in zip(records, verdicts):
        if verdict is None or verdict["rule"] not in OPEN_RULES:
            continue
        buckets.setdefault((verdict["rule"], verdict["detail"]), []).append(
            record.get("head") or "")

    print("%s\n%d open of %d judgments\n"
          % (path, sum(len(v) for v in buckets.values()), len(records)))
    for (rule, detail), heads in sorted(buckets.items(),
                                        key=lambda kv: -len(kv[1])):
        print("%5d  %s%s" % (len(heads), rule, ": %s" % detail if detail else ""))
        for example in sorted(set(heads))[:3]:
            print("       %s" % shorten(example))
    return 0


def regress(path=None):
    """Compare the judgment that was stored with the one the parser gives now.

    The log holds both halves of the suite -- what must keep being refused and
    what must keep being auto-allowed -- so a parser change that flips either
    direction shows up here. The first list is the one to read line by line: it
    is exactly what was just opened up.
    """
    path = path or log_path()
    if not path:
        print("logging is disabled (%s)" % LOG_ENV)
        return 1
    records = load_judgments(path)
    verdicts = replay(records)

    opened, closed, moved, unreplayable = [], [], 0, 0
    for record, verdict in zip(records, verdicts):
        # A collected body is not a change of mind, and counting it as one
        # fills the list this exists to be read line by line.
        if verdict is not None and verdict["rule"] == UNREPLAYABLE_RULE:
            unreplayable += 1
            continue
        was_allowed = record.get("rule") == CLASSIFIER_ALLOW_RULE
        now_allowed = verdict is None
        if was_allowed == now_allowed:
            if not now_allowed and verdict["rule"] != record.get("rule"):
                moved += 1
            continue
        (opened if now_allowed else closed).append((record, verdict))

    print("%s\n%d judgments replayed, %d skipped (body collected)\n"
          % (path, len(records), unreplayable))
    print("refused -> auto-allowed: %d  (read every one for a write)"
          % len(opened))
    for record, _ in opened:
        print("  %-46s %s" % (shorten(record.get("rule"), 46),
                              shorten(record.get("head"), 60)))
    print("\nauto-allowed -> refused: %d" % len(closed))
    for record, verdict in closed:
        print("  %-46s %s" % (shorten(verdict["rule"], 46),
                              shorten(record.get("head"), 60)))
    print("\nstill refused under a different rule: %d" % moved)
    return 0


def migrate(path=None):
    """Fold the two legacy logs into judgments.jsonl, replaying as it goes.

    What the parser now settles by itself is not carried over in either
    direction: a denial it would allow today would sit in the open list forever
    describing a question already answered, and a classifier verdict it can now
    express is a promotion that already happened. Both survive in the `.0`
    files this leaves behind, which is also what makes a second run a no-op.
    """
    import os

    path = path or log_path()
    if not path:
        print("logging is disabled (%s)" % LOG_ENV)
        return 1
    directory = os.path.dirname(path) or "."

    def legacy(name):
        source = os.path.join(directory, name)
        if os.path.abspath(source) == os.path.abspath(path):
            return []  # the destination is the source; nothing to fold in
        return load_log(source)

    skipped = 0

    def bodyless(record):
        # A legacy line with no command carries nothing to replay or store.
        # Counted apart from the drops, which are a statement about the parser.
        command = record.get("command")
        return not isinstance(command, str) or not command

    moved = dropped = 0
    records = legacy("denied.jsonl")
    for record, verdict in zip(records, replay(records)):
        if bodyless(record):
            skipped += 1
            continue
        if verdict is None:
            dropped += 1
            continue
        record_judgment(record["command"], verdict["rule"], verdict["detail"],
                        record.get("cwd"), record.get("ts"))
        moved += 1

    kept = shed = 0
    records = legacy("allowed.jsonl")
    for record, verdict in zip(records, replay(records)):
        if bodyless(record):
            skipped += 1
            continue
        if verdict is None:
            shed += 1
            continue
        record_judgment(record["command"], CLASSIFIER_ALLOW_RULE,
                        record.get("name"), record.get("cwd"),
                        record.get("ts"))
        kept += 1

    archived = []
    for name in ("denied.jsonl", "denied.jsonl.1",
                 "allowed.jsonl", "allowed.jsonl.1"):
        source = os.path.join(directory, name)
        if os.path.abspath(source) == os.path.abspath(path):
            continue
        try:
            os.replace(source, source + ".0")
            archived.append(name + " -> " + name + ".0")
        except OSError:
            continue

    print("%s\ndenials: %d carried, %d dropped (the parser allows them now)\n"
          "classifier verdicts: %d carried, %d dropped (the parser expresses "
          "them now)" % (path, moved, dropped, kept, shed))
    if skipped:
        print("skipped: %d legacy lines carried no command" % skipped)
    for line in archived:
        print("archived: %s" % line)
    return 0


# ---------------------------------------------------------------- entrypoint

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return
    verdict = explain(command, cwd=payload.get("cwd"))
    reason = "plan mode: read-only command"
    if verdict is not None:
        # Nothing above this line costs a network round trip, and the classifier
        # only ever sees what was already headed for a permission prompt.
        if not llm_second_opinion(command, verdict, payload.get("cwd")):
            log_denial(command, verdict, payload.get("cwd"))
            return
        reason = "plan mode: read-only command (classifier)"
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
        }
    }))


REPORTERS = {
    "--report": report,
    "--open": open_report,
    "--regress": regress,
    "--migrate": migrate,
}

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in REPORTERS:
        sys.exit(REPORTERS[sys.argv[1]](
            sys.argv[2] if len(sys.argv) > 2 else None))
    main()
