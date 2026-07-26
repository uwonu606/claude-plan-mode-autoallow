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
    "type", "date", "pwd", "basename", "dirname", "realpath", "readlink",
    "echo", "printf", "true", "false", "test", "[", "[[", "seq", "column",
    "comm", "join", "paste", "nl", "tac", "rev", "md5sum", "sha256sum",
    "cksum", "cd", "pushd", "popd", "hostname", "uname", "whoami", "id",
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
}
GIT_FLAGS_WITH_VALUE = {"-C", "--git-dir", "--work-tree", "--namespace"}
GIT_BRANCH_MUTATE = {"-d", "-D", "-m", "-M", "-c", "-C", "-f", "--delete",
                     "--move", "--copy", "--force", "--unset-upstream",
                     "--edit-description"}

FIND_BAD = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls",
            "-files0-from"}

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

# rg can execute a preprocessor binary and read archives through helpers.
RG_BAD_FLAGS = {"--pre", "--pre-glob", "--hostname-bin", "-z", "--search-zip"}

# file(1) opens attacker-named paths through these.
FILE_BAD_FLAGS = {"-m", "--magic-file", "-f", "--files-from"}

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

SUBST_PLACEHOLDER = "\x00SUBST\x00"

# Command names accepted while validating the current line, for the
# cross-command checks in check_whole_line(). Reset by is_read_only().
SEEN_COMMANDS = []


class Deny(Exception):
    pass


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
            raise Deny("heredoc")

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
        raise Deny("output redirection to %r" % target)
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


def check_find(args):
    for a in args:
        if a in FIND_BAD or a.startswith("-fprint"):
            raise Deny("find %s" % a)


def check_sort(args):
    for a in args:
        if a in ("-o", "--output") or a.startswith("--output="):
            raise Deny("sort writes to a file")
        if a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
            raise Deny("sort writes to a file")


def check_awk(args):
    blob = " ".join(unquote(a) for a in args).lower()
    for bad in AWK_BAD:
        if bad in blob:
            raise Deny("awk program contains %r" % bad)
    i = 0
    while i < len(blob):
        if blob[i] == ">":
            if i + 1 < len(blob) and blob[i + 1] == "=":
                i += 2
                continue
            raise Deny("awk program contains a redirection")
        i += 1


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
            raise Deny("sed flag %s" % a)
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
    raise Deny("sed script not in the recognized read-only set: %r" % script)


def check_fd(args):
    for a in args:
        if a in FD_BAD or a.startswith("--exec"):
            raise Deny("fd %s" % a)


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
            raise Deny("unquoted glob next to %s can expand to a flag" % cmd)


def check_rg(args):
    for a in args:
        if a in RG_BAD_FLAGS or any(
            a.startswith(f + "=") for f in RG_BAD_FLAGS if f.startswith("--")
        ):
            raise Deny("rg %s" % a)


def check_file(args):
    for a in args:
        if a in FILE_BAD_FLAGS or any(
            a.startswith(f + "=") for f in FILE_BAD_FLAGS if f.startswith("--")
        ):
            raise Deny("file %s" % a)


def check_jq(args):
    for a in args:
        if a in JQ_BAD_FLAGS:
            raise Deny("jq %s" % a)
        for flag in JQ_BAD_FLAGS:
            if flag.startswith("--") and a.startswith(flag + "="):
                raise Deny("jq %s" % a)
        if a.startswith("-") and not a.startswith("--") and (
            "f" in a[1:] or "L" in a[1:]
        ):
            raise Deny("jq %s" % a)
    program = " ".join(unquote(a) for a in args if not a.startswith("-"))
    for bad in JQ_BAD_PROGRAM:
        if bad in program:
            raise Deny("jq program contains %r" % bad)


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
        raise Deny("gh api -X %s" % method)
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
        raise Deny("gh %s" % sub)

    allowed = GH_READ_SUBCOMMANDS[sub]
    if not allowed:
        return  # `gh status`, `gh version`
    action = next((unquote(a) for a in rest if not a.startswith("-")), None)
    if action not in allowed:
        raise Deny("gh %s %s" % (sub, action))


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
    if sub not in GIT_READ_SUBCOMMANDS:
        raise Deny("git %s" % sub)

    if sub == "config":
        if not any(r.startswith(("--get", "--list", "-l")) for r in rest):
            raise Deny("git config write")
    elif sub == "branch":
        # Listing forms only: any bare operand creates/renames a branch.
        for r in rest:
            if not r.startswith("-"):
                raise Deny("git branch operand")
            if r in GIT_BRANCH_MUTATE or r.startswith("--set-upstream"):
                raise Deny("git branch %s" % r)
    elif sub == "remote":
        action = next((r for r in rest if not r.startswith("-")), None)
        if action is not None and action not in ("show", "get-url"):
            raise Deny("git remote %s" % action)
    elif sub == "reflog":
        action = next((r for r in rest if not r.startswith("-")), None)
        if action is not None and action != "show":
            raise Deny("git reflog %s" % action)


CHECKERS = {
    "find": check_find,
    "sort": check_sort,
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
        name = a.split("=", 1)[0]
        if name not in ENV_PREFIX_OK and not name.startswith("LC_"):
            raise Deny("%s= prefixes a command" % name)

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
            raise Deny("path-qualified command %r" % cmd)
        cmd = cmd.rsplit("/", 1)[1]

    if cmd in WRAPPERS:
        rest = list(args)
        if cmd == "env":
            while rest and (rest[0].startswith("-") or is_assignment(rest[0])):
                if rest[0] in ("-u", "--unset"):
                    rest = rest[2:]
                    continue
                rest = rest[1:]
            if not rest:
                return  # plain `env` dumps the environment
            return validate_command(rest, depth + 1)
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if cmd == "timeout" and rest:
            rest = rest[1:]  # duration argument
        if not rest:
            raise Deny("%s without a command" % cmd)
        return validate_command(rest, depth + 1)

    if cmd in GLOB_SENSITIVE:
        check_glob_sensitive(cmd, args)

    if cmd in CHECKERS:
        SEEN_COMMANDS.append(cmd)
        CHECKERS[cmd](args)
        return

    if cmd in ALWAYS_OK:
        SEEN_COMMANDS.append(cmd)
        return

    raise Deny("command not on read-only allowlist: %r" % cmd)


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


def check_whole_line():
    """Cross-command rules that only make sense once the line is fully parsed.

    Both mirror checks Claude Code itself applies: `cd` followed by `git` can
    run hooks/fsmonitor from the target directory, and more than one `cd` in a
    line makes the effective working directory hard to reason about.
    """
    cds = SEEN_COMMANDS.count("cd") + SEEN_COMMANDS.count("pushd")
    if cds > 1:
        raise Deny("multiple directory changes in one command")
    if cds and "git" in SEEN_COMMANDS:
        raise Deny("cd before git can execute hooks from the target directory")


def is_read_only(command):
    if not command or not command.strip():
        return False
    del SEEN_COMMANDS[:]
    try:
        validate_line(command)
        check_whole_line()
        return True
    except Deny:
        return False
    except RecursionError:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------- entrypoint

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return
    if is_read_only(command):
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "plan mode: read-only command",
            }
        }))


if __name__ == "__main__":
    main()
