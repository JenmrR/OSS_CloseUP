# npm·GitHub 유지보수 정보 저장

기준 feat/package-storage 73d9a55. DB v2를 그대로 사용합니다.

## 적용

.env의 GITHUB_TOKEN에 공개 저장소를 읽을 수 있는 토큰을 설정합니다.
토큰을 채팅·코드·커밋에 넣지 않습니다. backend에는 토큰을 전달하지 않습니다.
기존 토큰이 있으면 그대로 사용합니다.

```bash
docker compose up -d --build backend worker
docker compose exec worker python -m app.maintenance 702c92a6-51e2-40a8-9b29-528d1e58130a
curl -sS 'http://localhost:8000/scans/702c92a6-51e2-40a8-9b29-528d1e58130a/maintenance?limit=2' | python3 -m json.tool
```

기존 scan은 다시 스캔하지 않습니다. 먼저 package_storage가 끝난 scan에 실행합니다.
같은 scan/package는 UPSERT하므로 다시 조회하면 기존 행을 갱신합니다.
조회 도중 이미 저장한 패키지는 보존되며, 재실행으로 전체를 갱신할 수 있습니다.
새 업로드는 package_storage 다음에 유지보수 조회를 자동 실행합니다.

## 수집 기준

- 외부 패키지만 대상: root 제외. 기존 샘플 76개.
- npm /{name}/{installed_version}: 설치 버전의 deprecated 원문, repository 등 JSON 보존.
- name/version 일치 검증. 버전 정보 미확인 시 deprecated=NULL (정상으로 간주하지 않음).
- npm repository로 GitHub owner/repo 매핑. 다른 호스팅은 unsupported, 누락은 unmapped.
- GitHub: archived, default_branch, 해당 브랜치 최근 커밋 committer 날짜, latest 정식 릴리즈.
- repository.directory 보존. 모노레포 커밋/릴리즈는 저장소 전체 신호이며 특정 패키지의 갱신 시점이 아님.
- latest 릴리즈 404는 조회 가능한 최신 릴리즈 없음으로 기록. 유지보수 위험으로 단정하지 않음.
- 커밋 조회 실패 등은 github_status=failed로 표시하되 이미 확인한 archived 값은 유지.
- 라이선스/취약점/maintenance Finding을 만들거나 위험도 점수를 부여하지 않음.

## 실패·캐시

토큰이 없으면 npm만 조회하고 GitHub는 skipped/token_missing을 기록합니다.
401/403/429를 받으면 같은 실행에서 해당 호스트의 추가 요청을 중단하고 실패를 기록합니다.
HTTP 요청당 timeout 15초, 응답 최대 5 MiB, 리다이렉트 최대 4회이며 같은 HTTPS 호스트만 허용합니다.
사용자 repository URL을 직접 호출하지 않고 npm/GitHub의 고정 호스트에서만 읽습니다.
GitHub 토큰은 api.github.com에만 보내며 private 응답은 저장하지 않습니다.

동일 URL 성공 응답은 worker 프로세스 메모리에서 1시간 재사용합니다(최대 2048건).
중복 패키지/동일 repository 요청을 줄이며, 관측 시각은 원래 조회 시각을 보존합니다.
CLI 재실행·worker 재시작 시 캐시는 초기화됩니다. 지속 디스크 캐시는 아직 없습니다.

## 조회

GET /scans/{scan_id}/maintenance?limit=100&offset=0

패키지별 github_status/npm_status와 오류 사유·관측 시각을 제공합니다.
아직 수집되지 않은 패키지도 pending으로 표시합니다. null은 false와 다릅니다.
원시 JSON은 maintenance_signals.raw_npm_response/raw_github_response에 보관합니다.
전체 scan 상태는 취약점 정규화 미연결로 partial을 유지합니다.

## 검증

```bash
PYTHONPATH=backend:. python -m pytest backend/tests worker/tests -q
```

50개 통과: 기존 32개 및 repository 매핑·설치 버전·deprecated·부분 실패·릴리즈 없음·토큰 격리·캐시·요청 중단·리다이렉트 테스트.
테스트의 HTTP/DB는 mock입니다. 토큰 인증 실조회와 실제 DB 저장은 사용자 환경에서 확인해야 합니다.
공식 API 참고:
- https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
- https://docs.github.com/en/rest/repos/repos
- https://docs.github.com/en/rest/commits/commits
- https://docs.github.com/en/rest/releases/releases

## 저장소 404 대체 조회 보완

설치 버전의 GitHub 저장소가 404인 경우에만 동일 npm 패키지의 /latest 메타데이터를 조회합니다.
다른 GitHub 저장소가 명시돼 있고 실제 조회가 성공하면 현재 유지보수 조회 대상으로 사용합니다.
설치 버전·deprecated와 raw_npm_response는 그대로 유지합니다. 최신 버전으로 업그레이드하지 않습니다.
원래 주소, 404 응답, 최신 메타데이터와 버전, 대체 조회 응답을 raw_github_response에 보존합니다.
조회 API의 repository_mapping.source=npm_latest_fallback으로 대체 출처를 표시합니다.
이는 현재 패키지 저장소라는 근거이며 구버전 코드의 동일성·공식 이전을 증명하지 않습니다.
401/403/429는 대체 조회하지 않습니다. 최신 정보/후보 조회 실패 시 원래 404 상태를 유지합니다.

보완 테스트 포함 총 59개 통과(HTTP/DB mock). 실제 인증 조회·저장은 적용 후 재확인합니다.
