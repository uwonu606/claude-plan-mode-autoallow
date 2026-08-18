# `cd` 뒤의 git을 대상 저장소 검사로 자동 허용한다

`cd before git can execute hooks from the target directory`는 미해결 명령의 두 번째로 큰 버킷이고, 22일치 267건 중 67건(25%)이다. 그런데 표본은 `git show`, `git ls-tree`, `git status`처럼 전부 읽기 전용이다. 규칙의 근거 자체는 실재한다 — `cd` 대상 저장소의 로컬 설정과 훅이 명령을 실행시킬 수 있다. 그래서 규칙을 걷어내는 대신 **위협을 실제로 확인한다**: 대상 저장소의 로컬 config와 훅을 읽어보고 깨끗하면 자동 허용한다. 검사는 셋이고 모두 통과해야 한다 — git이 값을 읽는 섹션 안의 키가 전부 무해 목록에 있을 것, 줄의 git 동사가 네트워크를 타지 않는 읽기 동사일 것, 대상에 실행 가능한 `post-index-change` 훅이 없을 것. 하나라도 확인할 수 없으면 거부한다(fail closed).

## Considered Options

**키 단위 정확 열거.** 처음 고른 방식이었고 실측에서 **자동 허용 0건**이 나와 버렸다. 실제 저장소의 로컬 config에는 `branch.<name>.vscode-merge-base`(VS Code), `remote.origin.glab-resolved-head`(glab), `lfs.repositoryformatversion`(git-lfs)처럼 서드파티 도구가 찍은 키가 늘 섞여 있어서, git 문서에 있는 무해 키만 열거하면 실저장소가 전부 탈락한다. 근본 원인은 "모르는 키"와 "위험한 키"를 같게 본 것이다 — git은 자기 네임스페이스만 읽으므로 남이 찍은 키는 실행 경로가 아니다. 그래서 허용 단위를 키에서 **섹션**으로 올렸다. git이 값을 읽는 섹션(`core` `alias` `include` `includeIf` `diff` `difftool` `merge` `mergetool` `filter` `credential` `http` `ssh` `url` `uploadpack` `receivepack` `protocol` `gpg` `sendemail` `pager` `man` `help` `browser` `guitool` `instaweb` `sequence` `imap` `svn` `svn-remote` `trace2` `safe` `fsmonitor` `web`) 안에서만 키를 검사하고, 그 밖의 섹션은 무시한다. 같은 로그에서 62건이 자동 허용됐다.

**세션 트리 하위만 자동 허용.** `cd` 대상이 현재 프로젝트 트리 안이면 통과. 구현이 가장 싸지만 실측 6건에 그쳤다 — 이 훅이 마찰을 겪는 자리가 대부분 형제 워크트리와 다른 저장소라서, 경로로 그은 선이 실제 사용과 어긋난다.

**`git -C <경로>` 재작성 유도.** 규칙을 그대로 두고 거부 사유로 대안 문법을 안내한다. 그러나 `git -C`도 대상 저장소의 설정을 읽으므로 위협이 사라지지 않는다. 규칙을 유지한 채 사람의 습관만 바꾸는 것은 안전 이득 없이 마찰만 옮긴다.

**그대로 둔다.** 25%의 마찰을 감수한다. 이 훅의 존재 이유가 "읽기는 묻지 않는다"인데 최대 마찰원을 남기는 선택이라, 다른 개선을 해도 체감이 바뀌지 않는다.

## Consequences

- 로그 267건 기준 `cd` 뒤 git 67건 중 **62건이 자동 허용**된다. 남는 5건은 대상 저장소가 이미 사라져 검사할 수 없는 것 4건과 네트워크 동사 1건이다. 앞의 넷은 fail closed가 의도대로 동작한 것이다.
- `remote.<name>.url`에 `ext::sh -c ...`를 넣으면 URL 자리의 명령이 실행된다. 이 경로는 **동사 제한으로 닫는다** — `show` `log` `ls-tree` `cat-file` `rev-parse` `status` `diff` `blame`처럼 네트워크를 타지 않는 읽기 동사는 remote 설정을 읽지 않는다. `fetch`·`ls-remote`는 자동 허용되지 않으며, 어차피 refs를 쓰므로 읽기 전용도 아니다. 섹션 목록에 `remote`를 넣지 않아도 되는 이유가 이것이다.
- **훅 검사를 `post-index-change` 하나로 좁힌 근거는 실측이다.** git 2.53.0의 훅 26개를 전부 설치한 저장소에 읽기 동사 23개를 돌려, `git status`만 `post-index-change`를 발화시키는 것을 확인했다(stat 캐시를 갱신하며 인덱스를 쓴다 — `do_write_locked_index`). 인덱스가 이미 최신이면 발화하지 않고, `--no-optional-locks`를 붙여도 발화하지 않는다. `git diff`·`git ls-files -m`·`git blame`은 인덱스가 낡아도 발화하지 않는다. 나머지 22개 동사는 어떤 훅도 부르지 않았다. **git이 읽기 경로에 새 훅을 붙이면 이 실측을 다시 해야 한다** — 여기 적힌 숫자가 그 재측정의 기준선이다.
- 그 결과 **git-lfs나 husky를 쓰는 저장소가 자동 허용된다.** 그 훅들(`post-checkout` `post-commit` `post-merge` `pre-push`)은 읽기 동사가 부를 수 없다. 실행 가능한 훅이 하나라도 있으면 거부하는 앞선 초안은 lfs 저장소를 전부 탈락시켰고, 좁힌 검사는 같은 이득을 내면서 엄격히 더 보수적이다.
- 검사에 대상 저장소당 subprocess가 붙는다. 정적 파서 자체는 ~14 ms이고, 이 비용은 `cd`와 git이 같은 줄에 있을 때만 든다.
- 전역 config는 검사하지 않는다. 현재 세션에도 이미 적용되고 있으므로 `cd`가 새로 여는 위협 표면이 아니다.
