# 우선순위 실제 서비스 연결

정민 님의 PR #1 (`1b92d6f`, priority-io-v2 / priority-v1)을 워커·DB·조회 API·화면·AI 보고서에 연결합니다. 계산 규칙은 PR 모듈을 그대로 사용하며 AI가 등급을 다시 정하지 않습니다.

## 동작

- 정상 저장·검증된 정규화 결과 뒤에 우선순위를 계산합니다. 전체 검사 상태와 취약점 검사 완료 상태를 구분합니다.
- CRITICAL/HIGH/MEDIUM/LOW는 모듈의 P0/P1/P2/P3를 사용합니다. UNKNOWN은 null을 유지합니다.
- 직접/간접 의존성으로 등급을 낮추지 않습니다. 같은 등급 안에서는 모듈이 저장한 순서를 사용합니다.
- 계산 이력과 패키지별 집계는 `priority_evaluations`에, 연결별 등급은 `finding_packages`에 저장합니다.
- 근거 스냅샷을 먼저 커밋합니다. 계산 결과·연결별 등급·현재 결과 표시는 한 트랜잭션으로 반영합니다.
- 저장 실패는 별도 이력으로 남깁니다. 이전 등급이 DB에 남아 있어도 최신 계산이 실패했다면 화면과 AI에는 현재 결과로 제공하지 않습니다.
- 워커 ID·실행 횟수·근거 지문을 검사하여 오래된 작업이나 바뀐 근거의 결과가 덮어쓰지 못하게 합니다.
- 상세 설명과 요약 보고서는 같은 공개된 우선순위를 사용합니다. 프롬프트·모델·자동 유료 호출 설정은 바꾸지 않습니다.
- 기존 검사에는 새 정규화 메타데이터가 없을 수 있습니다. 기존 근거를 덮어써 재계산하지 않고 새 업로드로 확인합니다.

## 패치 종류

- `week4-priority-integration.patch`: 이시연 브랜치의 `63de27f` 기준. PR #1 코드와 이 연결 작업을 모두 포함합니다.
- `week4-priority-wiring-only.patch`: PR #1의 `1b92d6f`를 이미 받은 경우 사용하는 연결 작업만의 패치입니다.

둘 중 하나만 적용합니다. 두 패치를 연달아 적용하지 마세요. GitHub PR 병합이나 원격 푸시는 수행하지 않았습니다.

## WSL 적용

패치를 `~/oss-closeup/week4-priority-integration.patch`로 저장한 후:

```bash
cd ~/oss-closeup &&
git apply --check ./week4-priority-integration.patch &&
git apply ./week4-priority-integration.patch
```

DB 변경은 기존 결과를 삭제하지 않는 새 테이블 추가입니다. 진행 중인 검사를 마친 뒤 아래를 실행합니다. DB 비밀번호 값은 출력하지 않습니다.

```bash
cd ~/oss-closeup &&
docker compose stop worker &&
docker compose up -d --wait db &&
docker compose exec -T db sh -c 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < db/oss_closeup_v2_2_priority.sql &&
bash scripts/enable-ai.sh backend &&
docker compose up -d --build worker
```

기존 AI 설정 스크립트는 모델 ID와 키를 다시 묻습니다. 키를 채팅·소스 코드에 붙이지 말고 터미널의 숨김 입력에 입력합니다. 이후 프론트 실행:

```bash
cd ~/oss-closeup/frontend &&
node --test tests/*.test.js &&
npx oxlint src &&
npm run build &&
npm run dev
```

새 업로드가 끝나면 ‘조치 우선순위 계산 완료’, 먼저 볼 항목의 순서, 상세의 P 등급을 확인합니다. AI 요약 생성은 수동이며 비용이 발생할 수 있습니다.

## 검증 범위

- 프론트: 64개 테스트, oxlint, Vite production build 통과.
- 백엔드: 프로젝트의 FastAPI 0.141.1로 전체 테스트 실행.
- 워커: Windows에서 실행 가능한 173개 테스트와 145개 subtest 통과. Linux 실행 파일·프로세스 그룹에 의존하는 scanner/종료 테스트는 별도 Linux 환경 검증 대상입니다.
- 분리된 PostgreSQL 18에서 실제 스키마를 생성하여 성공 저장, 롤백, 예전 등급 숨김, 오래된 작업자 차단, 근거 변경 차단, UNKNOWN, 정상 빈 결과를 검증합니다.
- 기록된 실제 스캐너 출력 105개를 정규화한 53개 항목이 DB→조회 API→AI 그룹/상세 입력까지 전달되는 테스트를 포함합니다. 새 스캐너 실행이나 실제 유료 AI 호출을 수행한 테스트는 아닙니다.
- 운영 Docker의 PostgreSQL 16에서는 위 마이그레이션과 새 검사로 최종 확인이 필요합니다.

PostgreSQL 테스트는 `PRIORITY_TEST_DSN`을 지정해야 실행되며, 무작위 이름의 전용 스키마를 만들고 그 스키마만 정리합니다. 운영 DB 대신 별도 테스트 DB를 사용하세요.

```bash
PYTHONPATH=.:worker python -m pytest worker/tests/test_priority_postgres.py -q
PYTHONPATH=.:worker python -m pytest worker/tests -q
PYTHONPATH=backend python -m pytest backend/tests -q
```

라이선스·유지보수 검토 정책의 별도 서비스 연결, 이전 검사와 연관분석, AWS 배포는 이번 연결 범위에 포함하지 않습니다.
