# claude-plan-mode-autoallow

**plan mode**를 권한 프롬프트가 끊지 않게 하는 Claude Code `PreToolUse` 훅. 쓰거나 지우거나 실행하는 명령에는 그대로 프롬프트를 띄운다.

plan mode에서 에이전트가 하는 일은 읽고 생각하는 것이지 기계를 바꾸는 것이 아니다. 그런데 `ls` 하나, `grep` 하나마다 권한 프롬프트가 뜰 수 있고, 그 프롬프트가 정확히 plan mode가 존재하는 이유인 탐색의 흐름을 끊는다. 이 훅은 읽기 전용 작업을 자동 승인하고, 정작 필요한 두 프롬프트만 남긴다 — `AskUserQuestion`과 마지막 계획 승인(`ExitPlanMode`).

plan mode 밖의 동작은 건드리지 않는다.

## 왜 `permissions.allow`가 아니라 훅인가

이유는 둘이고, 둘 다 겪고 나서 알았다.

**프리픽스 규칙으로는 셸 원라이너를 표현할 수 없다.** `Bash(...)` allow 규칙은 Claude Code가 명령에서 뽑아낸 "command prefix"에 매칭된다. 명령에 명령 치환이 들어 있으면 이 추출이 `command_injection_detected`를 반환하면서 프리픽스가 아예 없어지고, 그러면 *어떤* allow 규칙도 매칭될 수 없다. 추출에 성공하더라도 `for`로 시작하는 줄의 프리픽스는 `for`다. 아래는 실제로 쓰였던 명령인데, 순수 읽기지만 어떤 규칙으로도 허용할 수 없다:

```bash
for d in */; do n=${d%/}; g=$( [ -d "$n/.git" ] && echo git || echo "-" ); \
  sz=$(du -sh "$n" 2>/dev/null | cut -f1); echo "$n | $g | $sz"; done
```

**샌드박스 경로는 여기서 막혀 있다.** Claude Code는 샌드박스된 Bash를 자동 승인할 수 있지만(`sandbox.autoAllowBashIfSandboxed`), 그 경로의 진입점 두 곳이 모두 모드가 `plan`이면 빠져나간다. 남는 수단은 권한 규칙과 훅뿐이고, 규칙은 위에서 탈락했다.

## 왜 auto 모드로 해결하지 않는가

auto 모드의 권한 분류기는 대화 트랜스크립트를 입력으로 받는 2단계 **LLM 호출**이다. 판정 한 번마다 네트워크 왕복이 들고, 토큰을 쓰고, 트랜스크립트가 길어질수록 성능이 떨어지며(`Classifier transcript exceeded context window → falling back to manual approval`), API를 못 쓰면 fail closed로 떨어진다. 이 훅은 네트워크도 토큰도 없이 ~14 ms에 판정한다.

auto 모드에서 *공짜인* 절반 — Claude Code 내장 `isReadOnly` 검사 — 은 plan mode에서도 이미 돌고 있다. 이 훅은 그것의 대체재가 아니라, 그 검사가 거부하는 복합 명령을 덮는 물건이다.

## 무엇을 통과시키는가

한 줄 안의 **모든** 명령이 통과해야 그 줄이 허용된다. 따옴표를 인식하며 토큰화하고, `$(...)`는 재귀적으로 검증하며, 줄은 `; && || | & 개행 ( )` 기준으로 분리한다.

무조건 허용: 읽기 전용 도구 고정 목록(`ls cat head tail wc grep rg stat du df diff cut tr strings hexdump od …`). 여기에 더해 아래 명령들은 인자를 검사한 뒤 허용한다:

| 명령 | 거부 조건 |
|---|---|
| `find` | `-exec` `-execdir` `-ok` `-okdir` `-delete` `-fprint*` `-fls` `-files0-from` |
| `sort` | `-o` / `--output` |
| `awk` | 프로그램에 `system` `close(` `ENVIRON` `getline`, `>` 리다이렉션, `\|` 파이프 |
| `sed` | 출력/치환 스크립트의 좁은 형태를 벗어나는 것 전부 (`w FILE`과 `e`는 쓰기·실행) |
| `git` | 읽기 전용 서브커맨드 집합 밖의 서브커맨드; `-c` (`core.pager`에 셸 명령을 넣을 수 있음); `--output`; `branch`/`remote`/`reflog`의 변경 동작 |
| `jq` | `-f` `--rawfile` `--slurpfile` `-L` `--run-tests`; 프로그램 안의 `$ENV` / `include` / `import` |
| `rg` | `--pre` `--pre-glob` `--hostname-bin` `-z` `--search-zip` |
| `file` | `-m` `--magic-file` `-f` `--files-from` |
| `fd` | `-x` `-X` `--exec` `--exec-batch` |
| `tree` | `-o` |
| `uniq` | 두 번째 피연산자 (출력 파일이다) |
| `gh` | `GET`/`HEAD` 외의 메서드; 요청 필드(`-f`/`-F` — gh가 POST로 전환됨), 단 메서드가 명시적으로 GET이면 예외; `--input`; `graphql`; 읽기 전용 서브커맨드 집합 밖의 서브커맨드 |

`gh`는 따로 짚을 만하다. `gh api`는 GitHub API 전체에 대한 인증된 raw 클라이언트라, 할 수 있는 일이 곧 토큰의 스코프와 같다 — 흔한 `repo, workflow, gist, admin:public_key` 토큰이면 히스토리 재작성, `.github/workflows/*.yml` 쓰기(러너에서 저장소 시크릿을 쥔 채 임의 코드 실행), 계정에 SSH 키 추가가 전부 포함된다. `Bash(gh api *)` 같은 프리픽스 규칙으로는 "GET만"을 표현할 수 없고, 그래서 이 판정이 파서에 있어야 한다. 저장소 조사(`gh api repos/...`, `gh repo view`, `gh pr list`)는 통과하고, `gh api -X DELETE`, `gh repo create`, `gh pr merge`, `gh secret set`은 프롬프트로 간다.

무조건 거부: `/dev/null` 계열이 아닌 대상으로의 출력 리다이렉션, 히어독, 프로세스 치환, 백틱, 간접 실행(`$CMD`, `eval`), 인터프리터(`python3 -c`, `bash script.sh`), `xargs`, 그리고 목록에 없는 모든 명령.

Claude Code가 스스로 하는 검사를 그대로 따르는 줄 단위 규칙이 둘 있다:

- **`cd` 다음 `git`** 은 거부한다 — git은 대상 디렉터리의 hook과 fsmonitor를 실행할 수 있다.
- **`cd`가 두 번 이상**이면 거부한다 — 실효 작업 디렉터리를 따지기 어려워진다.

`VAR=value cmd` 형태의 선행 대입은 로케일·포맷 관련 변수로 제한한다. 이게 없으면 `PAGER='sh -c "exec sh"' git log`가 셸 탈출이 된다. 대입만 있는 세그먼트(`n=${d%/}`)는 제한하지 않는다. 셸 변수를 설정할 뿐 아무것도 실행하지 않기 때문이다.

`find` / `sort` / `sed` / `git` / `rg` 옆의 따옴표 없는 글롭은 거부한다. 글롭이 `-delete` 같은 파일명으로 확장될 수 있다. 따옴표로 감싼 글롭, 그리고 안전한 명령 옆의 글롭(`ls *.ts`, `cat *.md`)은 괜찮다.

## 위협 모델

이건 **계획 중인 에이전트가 실수로 파괴적인 명령을 돌리는 것을 막는 가드레일**이지, 작정한 공격자에 대한 방어가 아니다. 정적 문자열 분석이라 충분히 꼬면 통과한다. 진짜 경계가 필요하면 훅이 아니라 샌드박스나 VM을 써야 한다.

설계 편향은 default deny다. 파싱 불가·미지·모호한 것은 전부 평소의 프롬프트로 떨어진다. 오탐이 나면 프롬프트 한 번을 더 보는 비용이지만, 반대로 새면 승인하지 않은 명령이 실행된다.

## 설치

`bash`와 `python3`(표준 라이브러리만)가 필요하다. `jq`는 필요 없다.

```sh
git clone https://github.com/uwonu606/claude-plan-mode-autoallow
cd claude-plan-mode-autoallow
./install.sh
```

`install.sh`는 `hooks/`의 두 파일을 `~/.claude/hooks/`로 복사하고, 추가할 설정 스니펫을 출력한다. 직접 해도 된다 — `hooks/`를 아무 데나 두고 `~/.claude/settings.json`에 등록하면 된다:

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

`settings.example.json`의 `permissions.allow` / `permissions.deny` 블록도 한 번 읽어볼 만하다. allow 항목은 *일반* 모드에서도 프롬프트를 줄이고, deny 항목은 자격증명 파일을 읽지 못하게 막는다.

## 거부 로그

default deny라는 건 allowlist가 영원히 완성되지 않는다는 뜻이다 — 아직 못 본 읽기 전용 명령이 항상 남아 있다. 그래서 파서가 거부한 plan mode Bash 명령은 거부한 규칙과 함께 `~/.claude/plan-mode-autoallow-denied.jsonl`에 적립된다:

```json
{"ts":"2026-07-26T17:48:59+0900","reason":"command not on read-only allowlist: 'rm'","command":"rm -rf /tmp/x","cwd":"/srv/project"}
```

핵심은 이유 쪽이다. 셸 줄만 모아둔 로그는 *뭔가 프롬프트가 떴다*까지만 알려주지만, 이유가 붙으면 *어느 규칙과 다툴 것인지*가 나온다. allowlist를 넓힐지, 인자 검사를 완화할지, 그냥 둘지를 가르는 게 그 정보다.

분류하려면:

```sh
python3 hooks/readonly_cmd.py --report
```

이유별로 묶고 최빈 명령을 나열한다. 하루에 스무 번 걸리는 규칙과 한 번도 안 걸린 규칙이 나란히 보인다.

| | |
|---|---|
| 경로 | `PLAN_MODE_AUTOALLOW_LOG=/some/path`, 끄려면 `off`. `CLAUDE_CONFIG_DIR`이 설정돼 있으면 그 아래를 기본값으로 쓴다. |
| 로테이션 | 2 MB에서 `.jsonl.1`로 이름을 바꾸고 새로 시작한다. 한꺼번에 몰려도 정작 들여다보게 만든 항목을 버리지 않는다. |
| 권한 | `0600`으로 만든다. 명령줄 전체가 들어가므로 셸 히스토리처럼 다뤄야 한다. |
| 실패 | 쓸 수 없는 로그는 무시한다. 권한 판정을 바꾸거나 막는 일은 절대 없다. |

읽을 때 주의할 점 하나. 로그에 있다고 해서 반드시 프롬프트가 떴던 건 아니다. 훅이 침묵하면 판정이 평소 흐름으로 넘어가고, 거기서 `permissions.allow` 규칙이 덮었을 수 있다. 이 로그는 *이 파서가* 거부한 명령의 집합이고, 검토할 가치가 있는 것도 그 집합이다.

## 비용

WSL2에서 각 30회 측정:

| 경로 | 호출당 |
|---|---|
| plan mode가 아닌 모든 경우 | 1.1 ms |
| plan mode, 비-Bash 도구 | 1.0 ms |
| plan mode, Bash, 허용 | ~14 ms |
| plan mode, Bash, 거부 | ~15 ms |

bash 쪽 절반은 서브프로세스를 하나도 띄우지 않는다. `python3`는 plan mode의 Bash 호출에서만 시작한다. 거부 경로는 append 한 번이 더 드는데, 거기 필요한 모듈은 로깅 함수 안에서 import하므로 허용 경로가 그 비용을 내지 않는다.

## 테스트

```sh
python3 tests/test_readonly_cmd.py
```

allow 집합, 위에 적은 우회 기법들, 거부 로그, 그리고 회귀를 덮는 241개 케이스. 이 스위트가 잡아낸 버그 둘은 모두 명령을 잘못 *허용*하는 쪽이었다:

- `printf ... | exec python3 ...` — 파이프라인 안의 `exec`는 스크립트가 아니라 서브셸을 대체하므로, 스크립트가 계속 진행해 무조건 허용 줄까지 내려가 `rm -rf`를 승인했다.
- 토크나이저가 연산자 매칭보다 `isspace()`를 먼저 검사해서 개행이 공백으로 삼켜졌고, `ls\nrm -rf /tmp/x`가 `rm`을 인자로 가진 `ls`로 파싱됐다.

allowlist를 넓힐 때는 양방향으로 케이스를 추가할 것.

## 근거

allowlist는 직관으로 쓰지 않고 세 출처와 대조했다. Claude Code 자신의 읽기 전용 집합(2.1.220 바이너리에서 추출), [OpenAI Codex CLI의 `is_safe_command.rs`](https://github.com/openai/codex/blob/main/codex-rs/shell-command/src/command_safety/is_safe_command.rs), 그리고 거꾸로 쓴 [GTFOBins](https://gtfobins.github.io/) — 무해해 보이지만 파일을 쓰거나 셸을 띄울 수 있는 명령의 목록으로. 위의 인자 검사는 대부분 원래 설계가 아니라 이 대조에서 나왔다.

## 라이선스

MIT
