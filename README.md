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

auto 모드에서 빌려온 것은 판정 방식이 아니라 **계층 구조**다. 아래 "모르는 명령" 절을 보라 — 정적 파서가 공짜 관문 자리에 앉고, LLM은 파서가 명령어를 몰라서 거부한 것만 받는다. 켜는 것은 선택이고 기본값은 꺼져 있다.

## 무엇을 통과시키는가

한 줄 안의 **모든** 명령이 통과해야 그 줄이 허용된다. 따옴표를 인식하며 토큰화하고, `$(...)`는 재귀적으로 검증하며, 줄은 `; && || | & 개행 ( )` 기준으로 분리한다.

무조건 허용: 읽기 전용 도구 고정 목록(`ls cat head tail wc grep rg stat du df diff cut tr strings hexdump od …`). 여기에 더해 아래 명령들은 인자를 검사한 뒤 허용한다.

검사에는 방향이 둘 있다. **허용 목록**은 인정하는 것을 적고 나머지를 거부한다. **거부 목록**은 반대다. 앞의 것이 이 프로젝트의 편향과 같은 방향이라 기본으로 쓰지만, 안전한 표면이 너무 넓어 적어 내려갈 수 없는 곳에서는 거부 목록을 쓴다. `find`의 술어가 그렇다 — 위험한 것은 액션 여덟 개로 닫혀 있는데 무해한 것은 오십 개다.

| 명령 | 방향 | 무엇을 본다 |
|---|---|---|
| `sed` | 허용 | 인정하는 스크립트 형태와 플래그만. `w FILE`과 `e`는 쓰기·실행이다 |
| `git` | 허용 | 읽기 전용 서브커맨드 집합. `-c`는 `core.pager`에 셸 명령을 넣을 수 있어 거부 |
| `gh` | 허용 | 읽기 전용 서브커맨드 집합, `GET`/`HEAD` 메서드만 |
| `file` | 허용 | `-C`가 `magic.mgc`를 쓰고, `-S`는 file 자신의 seccomp 샌드박스를 끈다 |
| `sort` | 허용 | `-o`는 파일을 쓰고 `--compress-program`은 프로그램을 실행한다 |
| `awk` | 허용 | 플래그와 프로그램 본문 양쪽. gawk는 `-o` `-p` `-d`로 파일을 쓰고 `-l`로 공유 객체를 로드한다 |
| `date` | 허용 | `+FORMAT` 아닌 피연산자는 시계 설정이다 (BSD는 플래그 없이 그렇게 한다) |
| `find` | 거부 | `-exec` `-execdir` `-ok` `-okdir` `-delete` `-fprint*` `-fls` `-files0-from` |
| `jq` | 거부 | `-f` `--rawfile` `--slurpfile` `-L` `--run-tests`; 프로그램 안의 `$ENV` / `include` / `import` |
| `rg` | 거부 | `--pre` `--pre-glob` `--hostname-bin` `-z` `--search-zip` |
| `fd` | 거부 | `-x` `-X` `--exec` `--exec-batch` |
| `tree` | 거부 | `-o` |
| `uniq` | 거부 | 두 번째 피연산자 (출력 파일이다) |

`file` `sort` `awk` `date`가 허용 목록 쪽에 있는 이유는 넷 다 거부 목록으로 막다가 뚫렸기 때문이다. 넷의 공통점은 위험한 플래그가 액션처럼 생기지 않았다는 것이다 — `-C`는 이름만 보면 검사 옵션 같고, `--compress-program`은 성능 옵션 같다. 거부 목록은 그런 것을 미리 알아야만 막을 수 있다.

`gh`는 따로 짚을 만하다. `gh api`는 GitHub API 전체에 대한 인증된 raw 클라이언트라, 할 수 있는 일이 곧 토큰의 스코프와 같다 — 흔한 `repo, workflow, gist, admin:public_key` 토큰이면 히스토리 재작성, `.github/workflows/*.yml` 쓰기(러너에서 저장소 시크릿을 쥔 채 임의 코드 실행), 계정에 SSH 키 추가가 전부 포함된다. `Bash(gh api *)` 같은 프리픽스 규칙으로는 "GET만"을 표현할 수 없고, 그래서 이 판정이 파서에 있어야 한다. 저장소 조사(`gh api repos/...`, `gh repo view`, `gh pr list`)는 통과하고, `gh api -X DELETE`, `gh repo create`, `gh pr merge`, `gh secret set`은 프롬프트로 간다.

무조건 거부: `/dev/null` 계열이 아닌 대상으로의 출력 리다이렉션, 히어독, 프로세스 치환, 백틱, 간접 실행(`$CMD`, `eval`), 인터프리터(`python3 -c`, `bash script.sh`), `xargs`, 그리고 목록에 없는 모든 명령.

Claude Code가 스스로 하는 검사를 그대로 따르는 줄 단위 규칙이 둘 있다:

- **`cd` 다음 `git`** 은 거부한다 — git은 대상 디렉터리의 hook과 fsmonitor를 실행할 수 있다.
- **`cd`가 두 번 이상**이면 거부한다 — 실효 작업 디렉터리를 따지기 어려워진다.

`VAR=value cmd` 형태의 선행 대입은 로케일·포맷 관련 변수로 제한한다. 이게 없으면 `PAGER='sh -c "exec sh"' git log`가 셸 탈출이 된다. 대입만 있는 세그먼트(`n=${d%/}`)는 제한하지 않는다. 셸 변수를 설정할 뿐 아무것도 실행하지 않기 때문이다.

`env`도 같은 검사를 받는다. `env PAGER=... git log`는 `PAGER=... git log`와 같은 것이고, 앞에 `env`가 붙었다고 달라지지 않는다. `env`의 플래그 역시 허용 목록이다 — `-S`는 피연산자를 통째로 명령줄로 쪼개고(`env -S"touch x"`가 touch를 실행한다) `-a`는 `argv[0]`을 갈아치워 검사받은 이름과 실행되는 것을 어긋나게 한다.

`find` / `sort` / `sed` / `git` / `rg` 옆의 따옴표 없는 글롭은 거부한다. 글롭이 `-delete` 같은 파일명으로 확장될 수 있다. 따옴표로 감싼 글롭, 그리고 안전한 명령 옆의 글롭(`ls *.ts`, `cat *.md`)은 괜찮다.

## 모르는 명령 — 선택 사항인 LLM 계층

거부 로그에서 가장 큰 버킷은 언제나 `command not on read-only allowlist`이고, 그 안에 있는 것은 `docker`, `kubectl`, `terraform`처럼 서브커맨드를 봐야 판정할 수 있는 명령들이다. `docker ps`는 읽기고 `docker rm`은 아니다. 이런 명령마다 체커를 쓰는 일은 끝나지 않는다.

`PLAN_MODE_AUTOALLOW_LLM=on`을 주면 그 버킷만 `claude -p`로 재심한다. 기본값은 꺼져 있다.

```
파서 허용 ──────────────────────────────────────► allow   ~14 ms
파서 거부
 ├─ 구조적 거부 (리다이렉션·백틱·간접 실행 …) ──► 프롬프트. LLM 안 부름
 ├─ 파괴적 명령 이름 (rm dd chmod sudo sh …) ───► 프롬프트. LLM 안 부름
 └─ 명령어를 모름
      ├─ 이미 판정한 줄 ────────────────────────► allow   ~100 ms
      └─ 처음 보는 줄 ─► claude -p ─┬─ 읽기 전용 ─► 파서 재실행 ─► allow  ~5 s
                                     └─ 아님/실패 ─► 프롬프트
```

세 가지가 이 계층의 성격을 정한다.

**분류기는 명령 문자열만 본다.** cwd도 트랜스크립트도 넘기지 않는다. 판정 질문이 "이 줄이 기계를 바꾸는가"뿐이라 나머지는 답에 기여하지 않고, 파일이나 웹에서 들어온 텍스트가 분류기에 닿지 않으므로 프롬프트 인젝션 표면이 없다. 덤으로 명령 문자열이 그대로 캐시 키가 된다.

**YES는 줄을 승인하지 않는다.** 명령어 이름 하나를 이번 줄에 한해 허용 목록에 넣고 **파서를 다시 돌린다.** 통과해야만 승인이 나간다. 그래서 분류기가 `docker`를 인정해도 `docker ps | rm -rf /tmp/x`는 `rm`에서 막히고, `docker ps && cd /tmp && git log`는 `cd` 다음 `git` 규칙에서 막힌다. 분류기의 권한은 정확히 "이 이름은 읽는 명령이다"이고, 그게 물어본 전부다.

**실패는 전부 프롬프트로 수렴한다.** 바이너리가 없든, 네트워크가 끊겼든, 타임아웃이든, 응답을 못 읽든 승인이 안 나가고 평소 흐름으로 넘어간다. 이 계층은 프롬프트를 없앨 수만 있고, 실수로 건너뛰게 만들 수는 없다.

허용 판정은 `allowed.jsonl`에 쌓인다. 캐시이면서 동시에 정적 규칙 승격 후보 목록이다 — 여기 같은 명령어가 반복되면 파서에 넣을 때가 된 것이다. 대가는 오판 하나가 영속한다는 것이고, 그 대신 같은 줄이 오늘과 내일 다르게 판정되지 않는다. 지우면 다시 묻는다.

| | |
|---|---|
| 켜기 | `PLAN_MODE_AUTOALLOW_LLM=on`. 다른 값이나 미설정은 꺼짐 |
| 모델 | `claude -p --model haiku`, 도구 전부 비활성, 타임아웃 30초 |
| 인증 | Claude Code가 이미 쓰는 것. API 키도 데몬도 필요 없다 |
| 비용 | 호출당 5~6초. 첫 호출은 캐시 읽기 11k + 생성 8k, 두 번째부터는 읽기 19k + **생성 0**. 명령줄이 아니라 Claude Code 시스템 프롬프트가 차지하는 양이고, 별도 프로세스인데도 같은 디렉터리라면 프리픽스를 그대로 읽는다 |

`claude -p`를 훅에서 부르는 것이 재귀를 만들지는 않는다. 그렇게 뜬 세션은 기본 모드라 이 훅이 첫 줄에서 빠져나간다.

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
├─ denied.jsonl.1   2 MB 넘으면 밀려난 이전 파일
└─ allowed.jsonl    LLM 계층을 켰을 때만. 위의 "모르는 명령" 절 참조
```

두 파일이 답하는 질문이 다르다. `denied.jsonl`은 **아무도 허용하지 않은 것**이라 쓰기 명령이거나 아직 아무도 판단할 수 없는 것이고, `allowed.jsonl`은 **분류기는 읽기라고 했는데 파서가 표현하지 못한 것**이라 정적 규칙으로 승격할 후보다.

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

`allowed.jsonl`이 있으면 이어서 명령어별로 묶어 보여준다. 이쪽 집계 키가 규칙이 아니라 **명령어 이름**인 이유는, 파서에 실제로 추가하게 되는 단위가 그것이기 때문이다:

```
6 classifier verdicts, 3 commands -- candidates to teach the parser:

    4  docker
       docker images
       docker logs web
       docker ps
       (+1 more)
    1  kubectl
       kubectl get pods
```

`docker`가 네 번 올라왔다는 건 이제 `check_docker`를 쓸 때가 됐다는 뜻이다. 쓰고 나면 그 줄들은 파서에서 ~14 ms에 끝나고 분류기를 부르지 않는다.

| | |
|---|---|
| 경로 | `PLAN_MODE_AUTOALLOW_LOG=/some/path`, 끄려면 `off`. `CLAUDE_CONFIG_DIR`이 설정돼 있으면 그 아래를 기본값으로 쓴다. 없는 상위 디렉터리는 만든다. |
| 로테이션 | 2 MB에서 `.jsonl.1`로 이름을 바꾸고 새로 시작한다. 한꺼번에 몰려도 정작 들여다보게 만든 항목을 버리지 않는다. |
| 권한 | 디렉터리 `0700`, 파일 `0600`. 명령줄 전체가 들어가므로 셸 히스토리처럼 다뤄야 한다. |
| 실패 | 쓸 수 없는 로그는 무시한다. 권한 판정을 바꾸거나 막는 일은 절대 없다. |

읽을 때 주의할 점 하나. 로그에 있다고 해서 그 명령이 실행되지 않은 건 아니다. 훅이 침묵하면 판정이 평소 흐름으로 넘어가고, 거기서 `permissions.allow` 규칙이나 세션 중 승인이 덮을 수 있다. 실세션 검증에서 실제로 그렇게 됐다 — 분류기가 거부한 `ollama pull …`이 `denied.jsonl`에 남았는데도 실행됐다. 이 로그는 *이 훅이* 승인하지 않은 명령의 집합이지 차단된 명령의 집합이 아니고, 검토할 가치가 있는 것은 그래도 그 집합이다.

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

allow 집합, 위에 적은 우회 기법들, 거부 로그, 그리고 회귀를 덮는 346개 케이스. 이 스위트가 잡아낸 버그 둘은 모두 명령을 잘못 *허용*하는 쪽이었다:

- `printf ... | exec python3 ...` — 파이프라인 안의 `exec`는 스크립트가 아니라 서브셸을 대체하므로, 스크립트가 계속 진행해 무조건 허용 줄까지 내려가 `rm -rf`를 승인했다.
- 토크나이저가 연산자 매칭보다 `isspace()`를 먼저 검사해서 개행이 공백으로 삼켜졌고, `ls\nrm -rf /tmp/x`가 `rm`을 인자로 가진 `ls`로 파싱됐다.

스위트가 놓친 것들도 있었다. 나중에 감사에서 나왔고, 하나는 스위트가 **적극적으로 감춘** 것이었다:

- `env PAGER='sh -c "exec sh"' git log` — 맨 앞 대입은 검사받는데 `env` 뒤의 대입은 검사 없이 버려졌다. 같은 공격에 네 글자만 붙이면 됐다. 스위트가 `env FOO=bar ls`를 허용 케이스로 갖고 있어서, 우회가 살아 있는 한 회귀 테스트가 영원히 통과했다.
- `env -S"touch pwned"` — 플래그를 다 떼고 나면 아무것도 안 남는데, 그것이 "맨몸 `env`"로 오인됐다.
- `file -C`, `sort --compress-program=sh`, `awk -f prog.awk` — 셋 다 거부 목록이 몰랐던 플래그다.
- `date -s`, `hostname pwned`, `/bin/../tmp/ls`.

allowlist를 넓힐 때는 양방향으로 케이스를 추가할 것. 그리고 **허용 케이스가 우회를 박아두고 있지 않은지** 볼 것 — 위 첫 항목이 그 경우였고, 스위트가 초록불인 채로 몇 달을 갔다.

이 스위트 안에서 LLM 분류기는 가짜로 갈아끼워져 있다. 여기서 볼 가치가 있는 것은 분류기 주변의 배선 — 무엇이 분류기까지 가고 무엇이 안 가는지, YES 뒤의 재실행이 나머지 규칙을 지키는지 — 이고 그건 결정적이어야 한다. 모델이 실제로 잘 답하는지는 다른 질문이라 따로 잰다:

```sh
python3 tests/eval_llm.py          # 전부
python3 tests/eval_llm.py docker   # 일부만
```

실제 호출이라 케이스당 몇 초와 토큰이 든다. 프롬프트를 고쳤을 때 돌리면 된다 — 조용히 나빠질 수 있는 것이 그것뿐이다. 각 도구의 읽기 형태와 쓰기 형태를 짝지어 두었다. 질문이 "docker가 안전한가"가 아니라 "서브커맨드를 봤는가"이기 때문이다. 마지막 측정은 47개 중 47개 정확, 호출당 평균 5.6초였다.

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

### LLM 계층 (2026-07-28)

`PLAN_MODE_AUTOALLOW_LLM=on`으로 켠 뒤 실제 plan mode 세션에서 확인했다. 시험 대상은 `ollama`다 — 이 머신에 실제로 설치돼 있고, 파서 목록에 없고, 파괴적 명령 하드 목록에도 없어서 정확히 분류기 몫으로 떨어지는 명령이었다. 판정의 증거는 두 로그다.

| 시도한 명령 | 기록된 곳 | 무엇이 확인되나 |
|---|---|---|
| `ollama list` | `allowed.jsonl` | 파서가 미지 명령으로 거부한 줄이 분류기를 거쳐 승인됐다 |
| `ollama list && echo … && wc -l < …` | `allowed.jsonl` | 복합 줄도 같은 경로를 탄다. `name`은 `ollama`로 귀속된다 |
| `ollama list` (같은 줄 재실행) | 기록 없음 | 캐시가 적중해 분류기를 부르지 않았다 |
| `ollama pull zzz-nonexistent-probe` | `denied.jsonl` | 분류기가 거부했고 훅은 승인을 내지 않았다 |

네 건 모두 설계대로 갈렸다. 특히 세 번째는 `allowed.jsonl`에 중복 레코드가 생기지 않는 것으로만 확인할 수 있는데, `record_allow`가 캐시 적중 시 건너뛰기 때문이다.

**여기서 확인되지 않는 것이 하나 있고, 그게 이 절 전체에 걸린다.** 권한 프롬프트가 화면에 떴는지는 에이전트 쪽에서 관측할 수 없다 — 도구 결과만 보면 "프롬프트 없이 통과"와 "프롬프트가 떠서 사용자가 승인함"이 똑같이 생겼다. 위 표가 증명하는 것은 **훅이 무엇을 결정했는가**까지고, 그 결정이 화면에서 어떻게 보였는지는 사람이 봐야 한다. 위쪽 항목들이 "프롬프트가 떴다"고 단정할 수 있는 이유는 사람이 그 자리에서 보고 적었기 때문이다.

실제로 네 번째 건은 훅이 승인하지 않았는데도 명령이 실행됐다. `settings.json`과 프로젝트 `.claude/settings.local.json` 어디에도 `ollama` 규칙이나 광범위한 `Bash(*)` 규칙은 없었으므로, 남는 설명은 프롬프트가 떠서 승인됐거나 세션 중 승인이 남아 있었거나 둘 중 하나다. 위 "거부 로그" 절의 마지막 문단이 경고하는 상황이 그대로 재현된 셈이다 — **로그에 거부로 남았다고 해서 그 명령이 실행되지 않았다는 뜻은 아니다.**

## 근거

allowlist는 직관으로 쓰지 않고 세 출처와 대조했다. Claude Code 자신의 읽기 전용 집합(2.1.220 바이너리에서 추출), [OpenAI Codex CLI의 `is_safe_command.rs`](https://github.com/openai/codex/blob/main/codex-rs/shell-command/src/command_safety/is_safe_command.rs), 그리고 거꾸로 쓴 [GTFOBins](https://gtfobins.github.io/) — 무해해 보이지만 파일을 쓰거나 셸을 띄울 수 있는 명령의 목록으로. 위의 인자 검사는 대부분 원래 설계가 아니라 이 대조에서 나왔다.

## 라이선스

MIT
