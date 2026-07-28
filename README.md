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

auto 모드의 권한 분류기는 대화 트랜스크립트를 입력으로 받는 2단계 **LLM 호출**이다. 모든 판정이 LLM을 타지는 않는다. 앞에 공짜 관문이 둘 있어서, 도구가 안전 목록에 있거나 모드를 `acceptEdits`로 바꿔 다시 검사했을 때 통과하면 거기서 끝난다(2.1.220 바이너리 기준). 문제는 이 훅이 겨냥하는 명령이 그 두 관문에 걸리지 않는다는 것이다. Bash는 안전 목록에 없고, 복합 명령은 위에서 본 프리픽스 추출 실패 때문에 `acceptEdits`에서도 자동 승인되지 않는다. 그래서 이런 줄은 auto 모드에서 매번 왕복을 문다 — 토큰을 쓰고, 트랜스크립트가 길어지면 컨텍스트를 넘겨 평소의 권한 처리로 떨어지고(`Auto mode classifier transcript too long, falling back to normal permission handling`), API를 못 쓰면 fail closed로 거부된다. 이 훅은 네트워크도 토큰도 없이 ~14 ms에 판정한다.

plan mode에는 Claude Code 내장 읽기 전용 검사가 이미 돌고 있다. 이 훅은 그것의 대체재가 아니라, 그 검사가 거부하는 복합 명령을 덮는 물건이다.

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

default deny라는 건 allowlist가 영원히 완성되지 않는다는 뜻이다 — 아직 못 본 읽기 전용 명령이 항상 남아 있다. 그래서 파서가 거부한 plan mode Bash 명령은 거부한 규칙과 함께 적립된다:

```
~/.claude/plan-mode-autoallow/
├─ README.md        install.sh가 쓴다. 이 디렉터리가 뭔지, --report를 어떻게 돌리는지
├─ denied.jsonl
└─ denied.jsonl.1   2 MB 넘으면 밀려난 이전 파일
```

로그를 훅 옆이 아니라 자기 디렉터리에 두는 이유는, 이 파일이 맥락 없이 발견되는 유일한 파일이기 때문이다. 몇 달 뒤 다른 걸 찾다가 `~/.claude`를 뒤지던 사람이 마주치는 자리에 설명이 같이 있어야 한다.

레코드 한 줄:

```json
{"ts":"2026-07-26T18:36:28+0900","rule":"command not on read-only allowlist","detail":"docker","reason":"command not on read-only allowlist: 'docker'","command":"docker ps","cwd":"/srv/project"}
```

`rule`과 `detail`이 나뉘어 있는 게 핵심이다. 파서의 거부 메시지는 대부분 값을 품는다 — `output redirection to 'a.txt'`, `find -delete`. 이걸 한 문장으로 저장하면 파일명 하나마다 별개의 버킷이 생겨서, 정작 이 로그를 읽는 이유인 *어느 규칙이 제일 자주 걸리나*에 답할 수 없다. `rule`은 값이 빠진 고정 문자열이라 집계 키가 되고, `detail`은 그 안에서 다시 묶인다. `reason`은 둘을 합친 문장인데, 이 파일을 처음 보는 방법이 대개 `tail`이기 때문에 남겨둔다.

집계해서 보려면:

```sh
python3 hooks/readonly_cmd.py --report
```

```
9  command not on read-only allowlist
   npm×2  rm×2  docker×1  python3×1  cargo×1  make×1  (+1 more)
3  output redirection to
   a.txt×1  b.txt×1  c.txt×1
2  gh
   pr merge×1  repo delete×1
```

규칙별 건수와 규칙 안의 값별 건수가 같이 나온다. 첫 줄이 `command not on read-only allowlist`이고 `detail`에 같은 명령이 반복되면 allowlist에 넣을 후보다. 로테이션된 `.1`도 같이 읽는다 — 오래 모인 데이터가 거기 있다.

| | |
|---|---|
| 경로 | `PLAN_MODE_AUTOALLOW_LOG=/some/path`, 끄려면 `off`. `CLAUDE_CONFIG_DIR`이 설정돼 있으면 그 아래를 기본값으로 쓴다. 없는 상위 디렉터리는 만든다. |
| 로테이션 | 2 MB에서 `.jsonl.1`로 이름을 바꾸고 새로 시작한다. 한꺼번에 몰려도 정작 들여다보게 만든 항목을 버리지 않는다. |
| 권한 | 디렉터리 `0700`, 파일 `0600`. 명령줄 전체가 들어가므로 셸 히스토리처럼 다뤄야 한다. |
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

allow 집합, 위에 적은 우회 기법들, 거부 로그, 그리고 회귀를 덮는 252개 케이스. 이 스위트가 잡아낸 버그 둘은 모두 명령을 잘못 *허용*하는 쪽이었다:

- `printf ... | exec python3 ...` — 파이프라인 안의 `exec`는 스크립트가 아니라 서브셸을 대체하므로, 스크립트가 계속 진행해 무조건 허용 줄까지 내려가 `rm -rf`를 승인했다.
- 토크나이저가 연산자 매칭보다 `isspace()`를 먼저 검사해서 개행이 공백으로 삼켜졌고, `ls\nrm -rf /tmp/x`가 `rm`을 인자로 가진 `ls`로 파싱됐다.

allowlist를 넓힐 때는 양방향으로 케이스를 추가할 것.

## 실세션 검증

훅의 판정은 JSON을 손으로 파이프해서 전부 확인할 수 있지만, 그것만으로는 정작 중요한 질문에 답하지 못한다. 라이브 페이로드에 `permission_mode` 필드가 실제로 오는가? Claude Code가 훅의 `allow` 결정을 실제로 존중하는가? 아래는 실제 세션에서 확인한 것들이다. 환경은 Claude Code 2.1.220, WSL2, 2026-07-26.

**훅은 실제로 발화한다.** plan mode에서 `for i in 1 2 3; do echo "tick $i"; done`이 프롬프트 없이 통과했다. `for`로 시작하는 줄은 어떤 프리픽스 규칙으로도 매칭되지 않고 내장 `isReadOnly` 검사는 복합 명령을 거부하므로, 이 줄을 통과시킬 수 있는 주체는 훅밖에 없다. `permission_mode` 필드가 페이로드에 존재한다는 것과 CLI가 훅의 `allow`를 존중한다는 것이 이 한 건으로 동시에 확인된다.

**거부 쪽도 실제로 막힌다.** plan mode에서 시도한 아래 두 명령 모두 권한 프롬프트가 떴고, 거부 로그에 이유가 남았다:

| 시도한 명령 | 로그에 기록된 이유 |
|---|---|
| `echo "hello" > /tmp/perm_test.txt` | `output redirection to '/tmp/perm_test.txt'` |
| `gh api -X POST repos/…/issues -f title=probe` | `gh api -X POST` |

**`permissions.deny`가 훅의 `allow`를 이긴다.** 훅은 plan mode에서 비-Bash 도구를 전부 자동 승인하지만, `permissions.deny`에 걸린 자격증명 파일 읽기는 그대로 거부됐다. 자동 승인이 deny 규칙에 구멍을 내지는 않는다는 뜻이다.

**`cd` 다음 `git`** 규칙도 이론이 아니다. 세션 중 `cd <dir> && git log …`가 실제로 프롬프트를 띄웠다.

**plan mode 밖은 그대로다.** `default` 모드에서 `ls`는 프롬프트 없이 통과하고 `find`는 프롬프트가 뜬다 — `settings.example.json`에서 `Bash(find:*)`를 뺀 결과다. `find . -delete`가 무프롬프트로 도는 것보다 프롬프트 한 번이 낫다.

같은 자리에서 `git -C <path> log`도 프롬프트가 떴다. `Bash(git log:*)` 규칙이 있는데도 그렇다. 추출된 프리픽스가 `git -C <path>`라 규칙과 어긋나기 때문이다. 프리픽스 규칙의 한계를 보여주는 사례가 하나 더 늘어난 셈인데, 같은 명령이 plan mode에서는 통과한다. 파서는 `-C`를 값을 받는 플래그로 알고 `log`를 서브커맨드로 읽는다.

**auto 모드에서는 이 훅의 효과를 측정할 수 없다.** `auto`의 LLM 분류기가 `find` 같은 명령을 알아서 승인해버리기 때문에, 무엇이 통과하고 무엇이 막히는지가 훅과 무관하게 결정된다. 훅의 동작을 확인하려면 `plan`에서, 일반 모드 회귀를 확인하려면 `default`에서 봐야 한다. `auto`에서 본 결과는 어느 쪽 증거도 되지 못한다.

## 근거

allowlist는 직관으로 쓰지 않고 세 출처와 대조했다. Claude Code 자신의 읽기 전용 집합(2.1.220 바이너리에서 추출), [OpenAI Codex CLI의 `is_safe_command.rs`](https://github.com/openai/codex/blob/main/codex-rs/shell-command/src/command_safety/is_safe_command.rs), 그리고 거꾸로 쓴 [GTFOBins](https://gtfobins.github.io/) — 무해해 보이지만 파일을 쓰거나 셸을 띄울 수 있는 명령의 목록으로. 위의 인자 검사는 대부분 원래 설계가 아니라 이 대조에서 나왔다.

## 라이선스

MIT
