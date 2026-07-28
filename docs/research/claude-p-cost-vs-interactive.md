# `claude -p`(headless)는 대화형 세션보다 비용이 더 드는가

조사일: 2026-07-27
검증 환경: `claude --version` → `2.1.220 (Claude Code)`

모든 주장은 공식 문서(code.claude.com, platform.claude.com, support.claude.com)를 근거로 하며 문장 끝에 출처를 표시했다. 1차 출처에서 확인되지 않은 내용은 **[추정]** 또는 **[미확인]**으로 명시했다.

---

## 결론 요약

**`-p` 플래그 자체에는 비용 프리미엄이 없다.** 과금은 호출 모드가 아니라 **인증 방식**으로 결정되고, 같은 토큰 수라면 `-p`와 대화형의 요금은 동일하다. Claude Code 문서 어디에도 `-p`와 대화형을 과금상 구분하는 서술이 없으며, 비용 문서는 "Claude Code charges by API token consumption"이라고만 말한다([costs](https://code.claude.com/docs/en/costs)).

**실제 비용 차이는 프롬프트 캐시 히트율에서 발생한다.** 그리고 흔한 통념과 달리, 별도의 `-p` 프로세스끼리도 캐시를 공유할 수 있다. Claude Code의 캐시 스코프는 "프로세스"가 아니라 **머신 + 작업 디렉터리**다:

> "In Claude Code, the cache is effectively scoped to one machine and directory. (…) Sessions you run in parallel in the same directory build matching prefixes and read each other's cache. Sequential sessions share the prefix only when the git status snapshot at startup matches, since the system prompt also captures branch and recent commits."
> — [Claude Code prompt caching § Cache scope](https://code.claude.com/docs/en/prompt-caching)

따라서 **더 비싸지는 조건은 다음 세 가지 중 하나에 해당할 때**다.

| 조건 | 왜 비싸지는가 |
|---|---|
| 호출 간격이 캐시 TTL을 넘김 | 시스템 프롬프트 + 프로젝트 컨텍스트 전체를 매번 재처리·재기록 |
| 호출 사이에 git 상태(브랜치/최근 커밋)나 작업 디렉터리가 바뀜 | 시스템 프롬프트 프리픽스가 달라져 순차 세션 간 캐시 미스 |
| API 키 인증인데 TTL을 기본 5분으로 둠 | 구독은 1시간 TTL이 자동인 반면 API 키는 5분이 기본 |

반대로 **같은 디렉터리에서, git 상태가 그대로이고, TTL 안에 반복 호출**하면 시스템 프롬프트·프로젝트 컨텍스트 레이어는 캐시에서 읽히고 대화 레이어만 새로 처리된다. 이 경우 반복 `-p`가 대화형보다 **오히려 쌀 수 있다** — 대화형 세션은 누적된 전체 대화를 매 턴 재전송하지만([costs § Why usage climbs in a long session](https://code.claude.com/docs/en/costs)), 단발 `-p`는 매번 짧은 대화 레이어에서 시작하기 때문이다. **[추정]** — 문서가 두 모드를 직접 비교하지는 않으며, 위 두 인용의 조합에서 도출한 결론이다.

**가장 실질적인 함정은 캐싱이 아니라 `--bare`다.** 뒤의 "과금 주체" 절 참조: `claude --bare -p`는 OAuth를 읽지 않으므로 구독으로 청구되지 않는다.

---

## 과금 주체 (구독 vs API 종량)

### 인증 방식이 과금을 결정한다

- Claude Code는 토큰 소비량으로 과금되며, 구독 플랜(Pro/Max/Team/Enterprise) 가격은 별도다: "Claude Code charges by API token consumption. For subscription plan pricing (Pro, Max, Team, Enterprise), see claude.com/pricing" ([costs](https://code.claude.com/docs/en/costs)).
- 조직 내에서 인증 수단이 섞여 있으면 **개발자별로 자신이 인증한 방식에 따라 계량**된다: "If your organization mixes sign-in methods, each developer is metered according to the one they authenticated with." ([costs § Manage costs for your organization](https://code.claude.com/docs/en/costs))
- 즉 `ANTHROPIC_API_KEY`가 설정돼 있으면 API 종량 과금, claude.ai 구독으로 로그인돼 있으면 플랜 사용량에서 차감된다. `-p`인지 대화형인지는 이 판정에 관여하지 않는다 **[미확인 — 문서에 모드별 구분이 명시적으로 부정된 것은 아니고, 구분한다는 서술이 없다]**.

### 구독 사용량 한도에 `-p`도 동일하게 계산된다

- 모든 Claude 제품 표면이 같은 한도를 공유한다: "Note that your usage of all different Claude product surfaces (claude.ai, Claude Code, Claude Desktop) counts towards the same usage limit." ([support: How do usage and length limits work?](https://support.claude.com/en/articles/11647753-how-do-usage-and-length-limits-work))
- Pro/Max 플랜 문서도 동일: "both Pro and Max plans offer usage limits that are shared across Claude and Claude Code, meaning all activity in both tools counts against the same usage limits." ([support: Use Claude Code with your Pro or Max plan](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan))
- 5시간 롤링 윈도 + 주간 윈도 구조는 Teams/Enterprise 서술에서 명시된다: "each member's Claude Code usage draws from a per-seat allowance that resets on a rolling five-hour window and a weekly window." ([costs § Claude for Teams and Enterprise](https://code.claude.com/docs/en/costs)) 개발자가 보게 되는 메시지도 `"You've hit your session limit"` / `"You've hit your weekly limit"`로 동일하다(같은 문서 § When a developer asks about a limit).
- **대화형 사용과 `-p` 사용을 한도 계산에서 구분한다는 서술은 어느 문서에도 없다.** 즉 `-p` 호출도 동일한 5시간/주간 한도를 소진한다고 보는 것이 타당하다 **[추정 — 명시적 부정 서술이 없다는 점에 근거]**.

### ⚠️ `--bare`는 구독 인증을 쓰지 않는다 (실무상 가장 큰 함정)

헤드리스 문서와 CLI 도움말이 일치한다:

> "Bare mode skips OAuth and keychain reads. Anthropic authentication must come from `ANTHROPIC_API_KEY` or an `apiKeyHelper` in the JSON passed to `--settings`."
> — [headless § Start faster with bare mode](https://code.claude.com/docs/en/headless)

`claude --help`의 `--bare` 설명도 동일하다: "Anthropic auth is strictly ANTHROPIC_API_KEY or apiKeyHelper via --settings (OAuth and keychain are never read)."

따라서 **`claude --bare -p`는 구독으로 청구되지 않고 API 종량으로 청구된다.** 그리고 문서는 `--bare`를 스크립트/SDK 호출의 권장 모드로 제시하며, 향후 `-p`의 기본값이 될 예정이라고 밝히고 있다: "`--bare` is the recommended mode for scripted and SDK calls, and will become the default for `-p` in a future release." (같은 문서)

→ 구독 요금제로 `-p`를 돌릴 생각이라면 `--bare`를 붙이지 말아야 하고, 향후 기본값 전환 시점을 주시해야 한다.

### 그 외 `-p` 모드의 과금 관련 제약

- `/usage-credits`는 API 키 인증에서는 아예 사용할 수 없고("the command isn't available with API key authentication"), Team/Enterprise 비-청구권한 멤버의 경우 `-p` 모드에서는 요청조차 전송되지 않는다: "in non-interactive mode with the `-p` flag and from Remote Control, the command sends no request and tells you to run it in an interactive session instead." ([costs § Add usage credits to your subscription](https://code.claude.com/docs/en/costs))

---

## 프롬프트 캐싱 차이

### 두 모드 모두 캐싱을 쓴다

Claude Code는 캐싱을 자동으로 관리하며, 모드별 차이에 대한 서술은 없다: "Claude Code handles prompt caching for you, unless you disable it." ([Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)) Agent SDK 문서도 동일하다: "The Agent SDK automatically uses prompt caching to reduce costs on repeated content. You do not need to configure caching yourself." ([agent-sdk cost-tracking § Track cache tokens](https://code.claude.com/docs/en/agent-sdk/cost-tracking))

### 캐시 가격 배수

| 항목 | 배수 (기본 입력가 대비) |
|---|---|
| 5분 TTL 캐시 쓰기 | 1.25× |
| 1시간 TTL 캐시 쓰기 | 2× |
| 캐시 읽기 | 0.1× |

출처: [API prompt caching § Pricing](https://platform.claude.com/docs/en/build-with-claude/prompt-caching). Claude Code 문서도 `cache_read_input_tokens`를 "billed at roughly 10% of the standard input rate"라고 서술한다([Claude Code prompt caching § Check cache performance](https://code.claude.com/docs/en/prompt-caching)).

### TTL은 인증 방식에 따라 자동 결정된다

| 인증 | 기본 TTL | 근거 |
|---|---|---|
| Claude 구독 | **1시간 (자동)** | "On a Claude subscription, Claude Code requests the one-hour TTL automatically. Usage is included in your plan rather than billed per token, so the longer TTL costs you nothing extra" |
| 구독 + usage credits 소진 중 | 5분으로 강등 | "If you've gone over your plan's usage limit and Claude Code is drawing on usage credits, you are billed for that usage, so Claude Code automatically drops the TTL to five minutes." |
| API 키 / Bedrock / Google Cloud / Foundry | 5분 | "you pay the per-token rates, so the TTL stays at the cheaper five minutes by default. To opt into the one-hour TTL, set `ENABLE_PROMPT_CACHING_1H=1`." |

출처: [Claude Code prompt caching § Cache lifetime](https://code.claude.com/docs/en/prompt-caching). 강제 5분은 `FORCE_PROMPT_CACHING_5M=1`, 캐싱 비활성화는 `DISABLE_PROMPT_CACHING=1`(모델별 변형 존재).

TTL은 **비활성 시간** 기준이며 히트할 때마다 갱신된다: "Cached prefixes expire after a period of inactivity. Each request that hits the cache resets the timer, so the cache stays warm as long as you keep working." (같은 문서)

### 핵심: 캐시는 프로세스가 아니라 머신+디렉터리에 스코프된다

이것이 이 조사의 가장 중요한 발견이다. 별도의 `claude -p` 프로세스가 매번 새 세션을 시작하는 것은 맞지만, **그것이 곧 캐시 미스를 뜻하지는 않는다.**

> "In Claude Code, the cache is effectively scoped to one machine and directory. The system prompt embeds the working directory, platform, shell, OS version, and auto-memory paths, so two sessions in different directories build different prefixes and miss each other's cache. That includes worktrees of the same repository, since each worktree has its own working directory.
>
> Sessions you run in parallel in the same directory build matching prefixes and read each other's cache. **Sequential sessions share the prefix only when the git status snapshot at startup matches**, since the system prompt also captures branch and recent commits."
> — [Claude Code prompt caching § Cache scope](https://code.claude.com/docs/en/prompt-caching) (강조 추가)

하위 API 레벨의 캐시 범위는 더 넓다: "The underlying API cache is broader. Caches are isolated between organizations, and on some providers, between workspaces within an organization. Within those boundaries, any two requests with the same model and prefix read the same cache." (같은 문서) API 문서도 이를 확인한다: 캐시는 조직 간 격리되며 Claude API·Claude Platform on AWS·Microsoft Foundry에서는 워크스페이스 단위로도 격리된다([API prompt caching § Cache storage and sharing](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)).

**반복 `-p` 호출에 적용하면:**

- ✅ 같은 디렉터리 + git 상태 동일 + TTL 이내 → 시스템 프롬프트 + 프로젝트 컨텍스트 레이어 캐시 히트
- ❌ 호출 사이에 커밋을 하나 만들면 → git status 스냅샷이 바뀌어 순차 세션 간 캐시 미스. CI/자동화 파이프라인에서 흔한 함정 **[추정 — 문서는 "git status snapshot at startup matches" 조건만 명시하고, 커밋 생성이 이를 깬다는 구체 사례는 언급하지 않는다]**
- ❌ worktree마다 다른 디렉터리 → 서로 캐시 공유 안 됨 (문서에 명시)

### 캐시 레이어 구조

Claude Code는 변동이 적은 순서로 요청을 구성한다([Claude Code prompt caching § How the cache is organized](https://code.claude.com/docs/en/prompt-caching)):

| 레이어 | 내용 | 변하는 시점 |
|---|---|---|
| System prompt | 핵심 지침, 툴 정의, output style | 로드된 툴 정의 집합이 바뀌거나 Claude Code 업그레이드 시 |
| Project context | CLAUDE.md, auto memory, unscoped rules | 세션 시작, `/clear`, `/compact` 이후 |
| Conversation | 사용자 메시지, 응답, 툴 결과 | 매 턴 |

모델과 effort 레벨도 캐시 키의 일부다: "each model has its own cache", "each effort level has its own cache for the same model." (같은 문서)

### 서브에이전트는 구독에서도 5분 TTL

> "Subagents use the five-minute TTL even on a subscription, since the automatic one-hour TTL applies to the main conversation."
> — [Claude Code prompt caching § Subagents and the cache](https://code.claude.com/docs/en/prompt-caching)

서브에이전트는 자체 시스템 프롬프트/툴셋으로 독립된 캐시를 만들고 첫 호출은 캐시 히트가 없다. 반면 fork는 부모의 시스템 프롬프트·툴·대화 이력을 그대로 상속하므로 첫 요청이 부모 캐시를 읽는다(같은 문서).

---

## 반복 `-p` 호출 비용 구조

### 매 호출마다 로드되는 것

`-p`는 기본적으로 대화형과 **동일한 컨텍스트를 로드한다**:

> "Without it [`--bare`], `claude -p` loads the same context an interactive session would, including anything configured in the working directory or `~/.claude`."
> — [headless § Start faster with bare mode](https://code.claude.com/docs/en/headless)

`--bare`가 건너뛰는 항목(= 기본 `-p`에서는 로드되는 항목)은 CLI 도움말에 열거돼 있다: hooks, LSP, plugin sync, attribution, auto-memory, background prefetches, keychain reads, CLAUDE.md auto-discovery (`claude --help`, v2.1.220).

**토큰 규모는 [미확인]** — 시스템 프롬프트나 툴 정의가 대략 몇 토큰인지 명시한 공식 수치를 찾지 못했다. 세션 내에서 `/context`로 실측하라는 안내만 있다([costs § Reduce MCP server overhead](https://code.claude.com/docs/en/costs)).

한 가지 완화 요소: MCP 툴 정의는 기본적으로 지연 로드된다. "MCP tool definitions are deferred by default, so only tool names enter context until Claude uses a specific tool." ([costs](https://code.claude.com/docs/en/costs)) 그리고 지연된 툴은 캐시 프리픽스에 없으므로 서버 연결/해제가 캐시를 깨지 않는다([Claude Code prompt caching § Connecting or disconnecting an MCP server](https://code.claude.com/docs/en/prompt-caching)).

### 비용 측정: `--output-format json`

> "With `--output-format json`, the response payload includes `total_cost_usd` and a per-model cost breakdown, so scripted callers can track spend per invocation without consulting the usage dashboard."
> — [headless § Pipe data through Claude](https://code.claude.com/docs/en/headless)

**단, 이 값은 추정치다.** Agent SDK 문서가 경고를 명시한다:

> "The `total_cost_usd` and `costUSD` fields are client-side estimates, not authoritative billing data. The SDK computes them locally from a price table bundled at build time, so they can drift from what you are actually billed (…) Do not bill end users or trigger financial decisions from these fields."
> — [agent-sdk cost-tracking](https://code.claude.com/docs/en/agent-sdk/cost-tracking)

같은 경고가 `/usage`에도 적용된다: "Claude Code computes the dollar figure locally from token counts priced at standard list rates, so it doesn't reflect promotional pricing or contracted discounts and may differ from your actual bill." ([costs § Using the /usage command](https://code.claude.com/docs/en/costs))

캐시 효율 확인용 필드([agent-sdk cost-tracking](https://code.claude.com/docs/en/agent-sdk/cost-tracking), [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)):

- `cache_creation_input_tokens` — 이번 턴에 캐시에 쓴 토큰 (쓰기 요율)
- `cache_read_input_tokens` — 캐시에서 읽은 토큰 (입력가의 약 10%)
- `modelUsage` / `model_usage` — 모델별 분해. 서브에이전트 토큰을 포함하므로 트리 전체 회계에는 이 필드를 써야 한다. `usage` 필드는 최상위 루프만 세므로 중첩이 생기는 순간 과소계상된다.

판정 기준: "A high read-to-creation ratio means caching is working well. If creation stays high turn after turn, something is changing in your prefix." ([Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching))

### `-p` 단발 vs 대화형 누적의 트레이드오프

대화형(또는 `--continue`로 이어붙인) 세션의 비용 특성은 문서에 명시돼 있다:

> "Long context: Claude Code sends your full conversation with every message, so a one-line question in a session that has been open all day uses tokens for the whole conversation, not just the one line."
> — [costs § Why usage climbs in a long session](https://code.claude.com/docs/en/costs)

즉 긴 세션은 대화 레이어가 계속 커지고, 캐시 히트로 읽더라도 0.1× 요율이 누적된다. 반면 단발 `-p`는 대화 레이어가 매번 짧게 시작한다. **따라서 "반복 `-p`가 항상 더 비싸다"는 명제는 성립하지 않는다** — 캐시가 유지되는 조건에서는 오히려 반대일 수 있다. **[추정 — 문서가 두 패턴의 총비용을 직접 비교하지 않는다]**

---

## 완화 방법

### 1. 같은 디렉터리에서, git 상태를 바꾸지 않고, TTL 안에 호출

가장 근본적인 방법이다. 캐시 스코프 규칙(머신+디렉터리, git status 스냅샷 일치)을 만족시키면 별도 프로세스여도 시스템 프롬프트·프로젝트 컨텍스트가 캐시에서 읽힌다([Claude Code prompt caching § Cache scope](https://code.claude.com/docs/en/prompt-caching)).

### 2. API 키 인증이면 `ENABLE_PROMPT_CACHING_1H=1`

Agent SDK 문서가 이 시나리오를 정확히 지목한다:

> "Cache entries written by the SDK use a 5-minute TTL by default when you authenticate with an API key or run on Amazon Bedrock, Google Cloud's Agent Platform, or Microsoft Foundry. **If your workload runs many short sessions against the same system prompt and context with gaps longer than 5 minutes between them, the cache expires between sessions and each new session pays full input price.**"
> — [agent-sdk cost-tracking § Extend the prompt cache TTL to one hour](https://code.claude.com/docs/en/agent-sdk/cost-tracking) (강조 추가)

트레이드오프: 1시간 TTL 쓰기는 2×, 5분은 1.25×이므로 "higher write cost for more cache reads"의 교환이다(같은 문서). 구독 사용자는 이미 자동이므로 설정할 필요가 없다.

### 3. `--exclude-dynamic-system-prompt-sections` — 머신/디렉터리를 넘어 캐시 공유

시스템 프롬프트의 머신별 섹션(cwd, git 저장소 여부, 플랫폼, 셸, OS 버전, auto-memory 경로)을 첫 user 메시지로 옮겨, 정적 프리셋만 시스템 프롬프트에 남긴다.

CLI 도움말(v2.1.220): "Move per-machine sections (cwd, env info, memory paths, git status) from the system prompt into the first user message. Improves cross-user prompt-cache reuse. Only applies with the default system prompt (ignored with `--system-prompt`). (default: false)"

SDK 등가물은 `excludeDynamicSections: true` / `"exclude_dynamic_sections": True`이며, 문서가 취지를 설명한다: "The per-session context moves into the first user message, leaving only the static preset and your `append` text in the system prompt so identical configurations share a cache entry across users and machines." ([agent-sdk modifying-system-prompts § Improve prompt caching across users and machines](https://code.claude.com/docs/en/agent-sdk/modifying-system-prompts))

**트레이드오프(문서 명시):** "Instructions in the user message carry marginally less weight than the same text in the system prompt, so Claude may rely on them less strongly when reasoning about the current directory or auto-memory paths. Enable this option when cross-session cache reuse matters more than maximally authoritative environment context." (같은 문서)

이 옵션은 **git status 변화로 인한 순차 세션 캐시 미스 문제도 함께 해결한다** — git status가 시스템 프롬프트에서 빠지기 때문이다 **[추정 — 플래그 설명이 "git status"를 이동 대상에 포함하고 있다는 점에서 도출]**.

### 4. `--resume` / `--continue`로 세션 재사용

헤드리스 문서의 패턴([headless § Continue conversations](https://code.claude.com/docs/en/headless)):

```bash
claude -p "Review this codebase for performance issues"
claude -p "Now focus on the database queries" --continue

# 또는 세션 ID를 캡처해서 특정 세션 재개
session_id=$(claude -p "Start a review" --output-format json | jq -r '.session_id')
claude -p "Continue that review" --resume "$session_id"
```

주의점 두 가지:

- 세션 ID 조회는 현재 프로젝트 디렉터리(및 git worktree) 범위로 한정되므로 두 명령을 같은 디렉터리에서 실행해야 한다(같은 문서).
- **업그레이드 후 resume은 최악의 캐시 미스다:** "Resuming a session after an upgrade reprocesses the entire conversation history with no cache hits, since the history now sits behind a different system prompt. The cost scales with how long the resumed conversation is, so the first turn back into a long session can be the most expensive request you send." ([Claude Code prompt caching § Upgrading Claude Code](https://code.claude.com/docs/en/prompt-caching)) 자동 업데이트 타이밍을 제어하려면 `DISABLE_AUTOUPDATER=1`.

또한 `--continue`는 대화 레이어를 계속 키우므로 앞 절의 "long context" 누적 비용이 따라온다. 짧고 독립적인 작업의 반복이라면 굳이 이어붙이지 않는 편이 나을 수 있다 **[추정]**.

### 5. 세션 내 캐시를 깨는 동작 피하기

`-p` 한 번의 호출 안에서도 아래 동작은 캐시를 무효화한다([Claude Code prompt caching § Actions that invalidate the cache](https://code.claude.com/docs/en/prompt-caching)):

- 모델 전환 (`opusplan` 설정은 plan mode 진입/이탈마다 모델 전환이 발생)
- effort 레벨 변경
- fast mode 켜기 (대화당 1회 비용)
- MCP 서버 연결/해제 — 단 툴이 deferred면 무해
- MCP 서버를 제공하는 플러그인 활성화/비활성화
- 툴 전체 deny 규칙 추가 (`Bash`, `WebFetch` 같은 맨 이름)
- `/compact`
- Claude Code 업그레이드

반대로 **캐시를 유지하는** 동작: 파일 편집, 세션 중 CLAUDE.md 편집(단 변경분이 적용되지도 않음), output style 변경(마찬가지로 미적용), permission mode 변경, skill/command 호출, `/recap`, `/rewind`, 서브에이전트 스폰(부모 캐시 기준).

### 6. `--bare`는 비용이 아니라 시작 속도와 재현성을 위한 것

`--bare`의 목적은 "reduce startup time by skipping auto-discovery"이며 CI에서 머신마다 동일한 결과를 얻기 위한 것이다([headless](https://code.claude.com/docs/en/headless)). CLAUDE.md·hooks·MCP를 로드하지 않으므로 컨텍스트가 줄어 토큰도 줄겠지만 **[추정 — 문서는 토큰 절감을 `--bare`의 효과로 서술하지 않는다]**, 앞서 지적한 대로 **구독 인증을 쓸 수 없게 되는 부작용**이 훨씬 크다.

---

## 실측 (2026-07-28, 이 저장소의 훅)

위 조사는 문서만 근거로 했고 "실제 `-p` 프롬프트는 비용 발생 우려로 실행하지 않음"이라고 적었다. 이 저장소가 [LLM 분류기 계층](../adr/0001-llm-classifier-behind-the-static-parser.md)에서 반복 `-p`를 실제로 쓰게 되면서 두 가지가 측정됐다. 조건: WSL2, 구독 인증, 같은 디렉터리, git 상태 불변, `--model haiku --max-turns 1 --output-format json`에 도구 전부 비활성.

### 미확인 1번 — 호출 1회의 토큰 규모

| | `cache_read` | `cache_creation` | `output` |
|---|---|---|---|
| 첫 호출 (cold) | 11,056 | 8,025 | ~85 |
| 이후 (warm) | 19,081 | **0** | ~85 |

명령줄 자체는 수십 토큰이고 나머지는 전부 Claude Code 시스템 프롬프트다. 중요한 것은 **warm에서 `cache_creation`이 0으로 떨어진다**는 것이다. 읽기가 입력가의 0.1×이고 쓰기가 1.25~2×이므로, 정상 상태의 호출은 첫 호출보다 훨씬 싸다. 위의 "캐시는 프로세스가 아니라 머신+디렉터리에 스코프된다"가 실제로 그렇게 동작한다는 확인이기도 하다 — 매 호출이 별도 프로세스인데도 두 번째부터 프리픽스를 그대로 읽는다.

### 완화책 3번은 이 사용 패턴에서 역효과

`--exclude-dynamic-system-prompt-sections`를 같은 조건에서 재보면:

| | `cache_read` | `cache_creation` |
|---|---|---|
| 첫 호출 | 13,988 | 5,003 |
| 두 번째 | 14,690 | **4,192** |

기본 배치가 두 번째부터 `cache_creation`을 0으로 만드는 반면 이쪽은 매 호출 4~5k를 계속 쓴다. 이유는 플래그의 동작 자체에 있다 — 동적 섹션을 **첫 user 메시지로 옮기는데**, 훅의 첫 user 메시지에는 판정할 명령줄이 들어 있어 호출마다 다르다. 옮겨진 내용이 변하는 레이어로 들어가 매번 재생성되는 것이다.

즉 이 플래그가 이득인 조건은 문서가 말하는 그대로 **user 메시지가 동일한 채로 여러 머신·사용자에 걸쳐 반복되는 경우**이고, 같은 머신에서 매번 다른 입력으로 부르는 경우에는 반대로 작용한다. 위 완화책 3번을 읽을 때 이 구분이 필요하다.

### `--bare` 확인

문서의 지적대로 구독 인증을 쓰지 못한다. 실행하면 다음에서 멈춘다:

```
$ claude --bare -p --model haiku 'Reply with exactly: OK'
Not logged in · Please run /login
```

`ANTHROPIC_API_KEY`가 없는 구독 사용자에게는 동작 자체가 안 된다는 뜻이라, 훅은 일반 `-p`를 쓴다.

---

## 출처 목록

Claude Code 문서 (code.claude.com):

- [Manage costs effectively](https://code.claude.com/docs/en/costs) — 토큰 과금 원칙, 조직별 계량, `/usage`, usage credits, 장시간 세션에서 사용량이 오르는 이유, 토큰 절감 전략
- [How Claude Code uses prompt caching](https://code.claude.com/docs/en/prompt-caching) — 캐시 레이어 구조, 무효화/유지 동작, **Cache lifetime**, **Cache scope**, 서브에이전트, 캐시 성능 확인
- [Run Claude Code programmatically (headless)](https://code.claude.com/docs/en/headless) — `-p` 사용법, `--bare`, `--output-format json`의 `total_cost_usd`, `--continue`/`--resume`
- [Track cost and usage (Agent SDK)](https://code.claude.com/docs/en/agent-sdk/cost-tracking) — `total_cost_usd` 추정치 경고, `usage`/`modelUsage` 차이, 캐시 토큰 필드, `ENABLE_PROMPT_CACHING_1H`
- [Modifying system prompts (Agent SDK)](https://code.claude.com/docs/en/agent-sdk/modifying-system-prompts) — Improve prompt caching across users and machines, `excludeDynamicSections`

Claude API 문서 (platform.claude.com):

- [Prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching) — 캐시 쓰기 1.25×/2×, 읽기 0.1×, 조직/워크스페이스 격리, 정확 일치 프리픽스 매칭, 최소 캐시 길이

Anthropic 지원 문서 (support.claude.com):

- [How do usage and length limits work?](https://support.claude.com/en/articles/11647753-how-do-usage-and-length-limits-work) — 모든 Claude 제품 표면이 동일 한도 공유
- [Use Claude Code with your Pro or Max plan](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan) — Pro/Max 한도가 Claude와 Claude Code 간 공유
- [Manage usage credits for paid Claude plans](https://support.claude.com/en/articles/12429409-extra-usage-for-paid-claude-plans) — usage credits (TTL 5분 강등 조건의 배경)

로컬 CLI:

- `claude --version` → `2.1.220 (Claude Code)`
- `claude --help` → `--bare`, `--exclude-dynamic-system-prompt-sections`, `-p/--print`, `--resume`, `--continue`, `--output-format`, `--max-budget-usd` 플래그 설명 (실제 `-p` 프롬프트는 비용 발생 우려로 실행하지 않음)

---

## 미확인 / 추가 확인이 필요한 항목

- 기본 `-p` 호출 1회의 시스템 프롬프트 + 툴 정의 토큰 규모 (공식 수치 없음). 세션에서 `/context`로 실측 필요.
- `-p`와 대화형의 총비용을 직접 비교한 공식 벤치마크나 서술은 존재하지 않는다. 본 문서의 비교 결론은 캐시 스코프 규칙 + 장시간 세션 누적 서술의 조합에서 도출한 추정이다.
- git 커밋 생성이 순차 세션 캐시를 깨는지에 대한 구체 사례. 문서는 "git status snapshot at startup matches" 조건만 명시한다.
- `-p` 호출이 구독 5시간/주간 한도에 계산된다는 **명시적** 문장. 모든 제품 표면이 같은 한도를 공유한다는 서술은 있으나 `-p`를 콕 집은 문장은 없다.
