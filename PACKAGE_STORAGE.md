# 패키지·Syft 라이선스 DB 저장

기준: feat/scan-worker fcabf77. DB v2 변경/재적용은 필요 없습니다.

## 적용 및 기존 검사 처리

```bash
docker compose up -d --build backend worker
docker compose exec worker python -m app.package_storage 702c92a6-51e2-40a8-9b29-528d1e58130a
```

기존 검사 명령은 도구를 재실행하지 않고 입력·Syft 원본의 해시를 검증해 저장합니다.
같은 명령을 다시 실행해도 (scan_id, lockfile_path)와 의존 관계 키로 UPDATE합니다.
package_id는 유지합니다. queued/running 검사의 수동 저장은 거부합니다.
새 업로드는 worker 도구 실행 후 자동 저장됩니다.

## 조회

GET /scans/{scan_id}/packages?limit=100&offset=0

응답: scan_id, total, limit, offset, package_storage, items.
items에는 이름·버전·경로·관계·purl·라이선스·근거가 있습니다.
조회 시 total은 루트를 포함합니다. 기존 샘플은 77행 = 루트 1 + 직접 10 + 간접 66입니다.

## 매핑 원칙

- lockfile packages 항목을 설치 경로별로 저장. 루트는 빈 경로와 relationship=root.
- 루트에서 선언한 의존성이 최상위 경로에 있을 때 direct. 나머지는 indirect.
- scoped 이름 및 npm alias의 실제 이름과 설치 이름을 구분.
- dependencies 테이블은 가장 가까운 설치 경로를 찾고, 없으면 상위 경로를 탐색.
- optional/peer 미설치 항목은 임의로 만들지 않고 unresolved_dependencies에 기록.
- Syft npm artifact의 이름·버전으로 찾고, integrity/resolved가 있으면 추가 대조.
- 여러 후보의 라이선스/purl이 다르면 ambiguous, 라이선스는 빈 배열.
- declared 라이선스의 SPDX 식 또는 원문 value 보존. OR/AND 식을 쪼개지 않음.
- Syft 없음·매칭 없음·라이선스 없음은 unknown. lockfile_license는 참고 근거로만 보존.
- Syft artifact ID, JSON pointer, 원문 라이선스와 scan_artifact ID를 근거로 연결.

## 범위

이번 코드는 packages/dependencies 저장입니다. 취약점 Finding 정규화, 위험도 판정,
GitHub 조회, AI 설명은 하지 않습니다. 전체 scan 상태는 여전히 partial일 수 있습니다.
root 항목은 UI의 외부 의존성 개수에서 제외해야 합니다.
API limit 최대 500. 전체 자료는 offset으로 나누어 조회합니다.

## 검증

```bash
python -m pip install -r backend/requirements.txt pytest httpx
PYTHONPATH=backend:. python -m pytest backend/tests worker/tests -q
```

32개 테스트 통과: 기존 API/worker 23개 + 매핑·저장 계약 9개.
실제 lock 샘플 77행, 중첩/스코프/alias, 출처 불일치, 상충 라이선스,
미설치 의존성, 실행 중 backfill 거부, 트랜잭션/UPSERT 구성을 확인했습니다.
DB 호출 테스트는 mock입니다. 실제 PostgreSQL 저장/재실행 검증은 아직 미완료입니다.
앞선 임시 PostgreSQL 실행은 자동 승인 검토 사용량 제한으로 실행되지 않았습니다.
로컬에서 같은 scan_id에 저장 명령을 두 번 실행하고, 조회 total이 증가하지 않는지 확인합니다.
