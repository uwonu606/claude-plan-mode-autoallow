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
}
GIT_FLAGS_WITH_VALUE = {"-C", "--git-dir", "--work-tree", "--namespace"}
GIT_BRANCH_MUTATE = {"-d", "-D", "-m", "-M", "-c", "-C", "-f", "--delete",
                     "--move", "--copy", "--force", "--unset-upstream",
                     "--edit-description"}

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

SUBST_PLACEHOLDER = "\x00SUBST\x00"

# Command names accepted while validating the current line, for the
# cross-command checks in check_whole_line(). Reset by is_read_only().
SEEN_COMMANDS = []


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


def walk_flags(args, exact_ok, with_value, cmd, value_hook=None):
    """Return the operands, refusing any flag that is not on the allowlist.

    Short flags bundle (`sort -rn`) and carry their value attached (`awk -F:`),
    so they are walked one character at a time rather than matched whole.
    Bundling is why the allowlist has to be consulted per letter: `-bi` must not
    be accepted just because neither `-b` nor `-i` is spelled out anywhere.

    `value_hook` maps a flag to a function that inspects its value, for the ones
    that carry something worth reading -- awk's `-e` takes a program.
    """
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if not a.startswith("-") or a == "-":
            return args[i:]

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
    return []


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
        raise Deny("gh %s", sub)

    allowed = GH_READ_SUBCOMMANDS[sub]
    if not allowed:
        return  # `gh status`, `gh version`
    action = next((unquote(a) for a in rest if not a.startswith("-")), None)
    if action not in allowed:
        raise Deny("gh %s %s", sub, action)


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
        SEEN_COMMANDS.append(cmd)
        return

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


def explain(command, extra_allowed=None):
    """None when the whole line is read-only, otherwise why it was rejected.

    `extra_allowed` adds one command name to the allowlist for this call only.
    It exists so a name the LLM classifier vouched for can be re-checked against
    every other rule rather than bypassing them.

    The reason is what makes the denial log worth keeping: it turns "this
    prompted" into "this prompted because `sed -i` writes in place", which is
    the difference between a log you can triage and a pile of shell lines.
    """
    if not command or not command.strip():
        return {"rule": "empty command", "detail": None,
                "reason": "empty command"}
    del SEEN_COMMANDS[:]
    added = extra_allowed and extra_allowed not in ALWAYS_OK
    if added:
        ALWAYS_OK.add(extra_allowed)
    try:
        validate_line(command)
        check_whole_line()
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

# Names that never reach the classifier, however it might vote. This is the list
# that decides how far a wrong answer can travel, so the membership rule has to
# be one thing rather than a feeling about each name.
#
# The rule: the name alone settles the question. `rm` is a deletion whatever
# follows it, `sudo` is an escalation, `sh` runs whatever it is handed. Asking a
# model about those is not a judgement call, and a yes is not a close call
# either -- it is a wrong answer.
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
LLM_HARD_DENY = {
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
LLM_HARD_DENY_PREFIXES = ("mkfs.", "fsck.", "mount.", "umount.")

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


def allowed_log_path(denied=None):
    """Sibling of the denial log, holding the commands the classifier passed."""
    denied = denied or log_path()
    if not denied:
        return None
    import os

    directory, name = os.path.split(denied)
    return os.path.join(directory, name.replace("denied", "allowed", 1)
                        if "denied" in name else "allowed.jsonl")


def cached_allow(command):
    """True when the classifier has already passed this exact command line.

    The cache is the record: an entry means a verdict was reached and stands
    until someone deletes the line. That is the point of keying on the exact
    string -- the same line gets the same answer today and next month, instead
    of a fresh roll of the dice each time it appears.
    """
    path = allowed_log_path()
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    if json.loads(line).get("command") == command:
                        return True
                except ValueError:
                    continue
    except (IOError, OSError):
        pass
    return False


def record_allow(command, name, cwd=None):
    """Append one verdict. Never raises -- the decision is already made."""
    try:
        import os
        import time

        path = allowed_log_path()
        if not path:
            return
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            if os.path.getsize(path) > LOG_MAX_BYTES:
                os.replace(path, path + ".1")
        except OSError:
            pass
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "name": name,
            "command": command,
        }
        if isinstance(cwd, str) and cwd:
            record["cwd"] = cwd
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n")
                     .encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:
        pass


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
    if not name or name in LLM_HARD_DENY:
        return False
    if name.startswith(LLM_HARD_DENY_PREFIXES):
        return False
    cached = cached_allow(command)
    if not cached and not llm_says_read_only(command):
        return False
    if explain(command, extra_allowed=name) is not None:
        return False
    if not cached:
        record_allow(command, name, cwd)
    return True


# ------------------------------------------------------------- denial log

# Commands that were not auto-allowed are appended here so the allowlist can be
# widened from evidence instead of guesswork. The log lives in its own directory
# rather than loose in ~/.claude: the rotated file is a second entry, and the
# directory gives the README a place to sit, so someone who finds the log
# without knowing the hook can work out what wrote it and how to read it.
LOG_ENV = "PLAN_MODE_AUTOALLOW_LOG"
LOG_DIRNAME = "plan-mode-autoallow"
LOG_BASENAME = "denied.jsonl"
LOG_MAX_BYTES = 2 * 1024 * 1024
LOG_OFF = {"", "off", "0", "no", "false", "none"}


def log_path():
    """Where to append denials, or None when logging is switched off."""
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


def log_denial(command, verdict, cwd=None):
    """Append one JSON line. Never raises -- logging must not gate a decision.

    Imports live in the function body: this runs only when a command was
    rejected, and the hook's cost is dominated by module import on the path
    that matters (a command that gets allowed).

    `rule` and `detail` are what make the file a dataset rather than a pile of
    sentences -- see report(). `reason` is kept alongside them because the first
    way anyone reads this file is `tail`, and a sentence survives that better
    than two fields the reader has to recombine.
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
        # Rotate rather than truncate, so a burst of denials cannot discard the
        # very entries that motivated looking at the file.
        try:
            if os.path.getsize(path) > LOG_MAX_BYTES:
                os.replace(path, path + ".1")
        except OSError:
            pass
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "rule": verdict["rule"],
            "detail": verdict["detail"],
            "reason": verdict["reason"],
            "command": command,
        }
        if isinstance(cwd, str) and cwd:
            record["cwd"] = cwd
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


def load_log(path):
    """Records from the log and its rotated predecessor, oldest first."""
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


def report(path=None):
    """Summarise the denial log: which rules fire, and on what.

    Grouped by `rule` rather than `reason`, because a rule that embeds a value
    -- "output redirection to 'a.txt'" -- would otherwise land in a bucket of
    one and never rise to the top of the list, which is the whole reason to
    read this file.
    """
    path = path or log_path()
    if not path:
        print("logging is disabled (%s)" % LOG_ENV)
        return 1
    records = load_log(path)
    if not records:
        print("%s: no entries" % path)
        return 0

    by_rule = {}
    for record in records:
        # Records written before rules were split carry only a reason.
        rule = record.get("rule") or record.get("reason", "?")
        detail = record.get("detail")
        counts = by_rule.setdefault(rule, {})
        counts[detail] = counts.get(detail, 0) + 1

    print("%s\n%d denials, %d rules, %s .. %s\n"
          % (path, len(records), len(by_rule),
             records[0].get("ts", "?"), records[-1].get("ts", "?")))
    for rule, details in sorted(by_rule.items(),
                                key=lambda kv: -sum(kv[1].values())):
        top = sorted((d for d in details.items() if d[0]), key=lambda kv: -kv[1])
        shown = "  ".join("%s×%d" % (d, c) for d, c in top[:6])
        if len(top) > 6:
            shown += "  (+%d more)" % (len(top) - 6)
        print("%5d  %s" % (sum(details.values()), rule))
        if shown:
            print("       %s" % shown)

    print("\nlast %d commands:" % min(10, len(records)))
    for record in records[-10:]:
        flat = " ".join(record.get("command", "").split())
        if len(flat) > 88:
            flat = flat[:85] + "..."
        print("  %s  %s" % (record.get("ts", "?")[:16], flat))
    report_allowed(path)
    return 0


def report_allowed(denied=None):
    """List what the classifier passed, grouped by command name.

    Printed with the denials because the two halves answer one question between
    them. The denial log says what nothing would allow; this says what the
    parser could not express but the classifier recognised, and the name is the
    aggregation key because the name is what would be added to the parser.
    """
    path = allowed_log_path(denied)
    if not path:
        return
    records = load_log(path)
    if not records:
        return

    by_name = {}
    for record in records:
        by_name.setdefault(record.get("name") or "?", []).append(
            record.get("command", ""))

    print("\n%s\n%d classifier verdicts, %d commands -- candidates to teach "
          "the parser:\n" % (path, len(records), len(by_name)))
    for name, commands in sorted(by_name.items(), key=lambda kv: -len(kv[1])):
        print("%5d  %s" % (len(commands), name))
        for example in sorted(set(commands))[:3]:
            flat = " ".join(example.split())
            if len(flat) > 80:
                flat = flat[:77] + "..."
            print("       %s" % flat)
        if len(set(commands)) > 3:
            print("       (+%d more)" % (len(set(commands)) - 3))


# ---------------------------------------------------------------- entrypoint

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return
    verdict = explain(command)
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


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--report":
        sys.exit(report(sys.argv[2] if len(sys.argv) > 2 else None))
    main()
