# 2주차 worker: 원시 검사 실행

기준 브랜치: feat/upload-api (336116d). DB v2를 그대로 사용하며 재적용/초기화하지 않습니다.

## 실행

```bash
docker compose up -d --build worker
docker compose logs --tail=80 -f worker
```

시작하면 기존 queued 요청도 자동 처리합니다. Ctrl+C는 로그 보기만 종료합니다.
GET /scans/{scan_id}의 tool_status로 도구별 진행 상황을 확인합니다.
첫 Trivy 취약점 DB 다운로드는 시간이 걸릴 수 있습니다. 도구별 제한 660초입니다.

## 이번 단계의 범위

- queued → running → partial/failed. UUID와 원본 SHA-256을 확인한 뒤 검사.
- 기존 run_sample_scan.sh의 Trivy/OSV/Syft 명령을 Python 어댑터로 옮김.
- OSV 종료 코드 1은 유효 JSON을 함께 생성한 경우 정상 처리.
- 도구별 실행 버전, 시작/종료, 종료 코드, 오류 상태를 scan_tool_runs에 저장.
- 결과 JSON, 로그, Syft SPDX SBOM을 results/{scan_id}/{attempt_count}/에 저장.
- scan_artifacts에 위치·SHA-256·크기 저장. 입력 종류는 /work/uploads 기준,
  raw_result/sbom/log는 /work/results 기준으로 해석.
- 한 도구 실패/타임아웃에도 나머지 도구 실행. 모든 도구 실패는 failed.
- 현재 정규화/Finding 저장 및 GitHub 조회는 미연결. 성공 도구가 있으면 partial.
  completed는 아직 사용하지 않음. 정상 결과를 취약점 0건으로 대신 표시하지 않음.

## 중복 실행 및 중단

MVP는 PostgreSQL 세션 advisory lock으로 활성 worker를 하나로 제한합니다.
추가 worker는 대기합니다. 같은 세션의 트랜잭션에서 SKIP LOCKED로 작업을 가져옵니다.
실행 중 heartbeat DB 쓰기가 실패하면 자식 프로세스 그룹을 종료하고 세션을 다시 연결합니다.
단절된 세션의 잠금이 DB에서 해제되어야 새 worker가 시작합니다.
새 활성 worker가 잠금을 잡으면 이전 running 검사·도구를 failed로 복구합니다.
자동 재시도는 하지 않습니다. 재검사가 필요하면 새 업로드로 새 scan_id를 만듭니다.
여러 검사를 병렬 수행하는 설계가 아니며, 이를 추가하려면 작업별 lease/fencing이 필요합니다.

## 다음 연결 지점

worker/app/main.py의 commands/run_tool이 현재 원시 실행 어댑터입니다.
정민님의 Trivy/OSV 모듈이 준비되면 입력 경로·출력 경로·결과·오류 계약을 맞춰 교체합니다.
정규화 결과를 packages/findings/finding_packages 등에 저장한 후에만 완료 판정을 확장합니다.
GitHub 조회, 원본 보관 기한·삭제, 결과 API·다운로드는 별도 작업입니다.
도구가 다운로드한 취약점 DB 버전은 아직 별도 수집하지 않으며 tool_version은 CLI 출력입니다.

## 검증과 한계

worker 테스트 8개: OSV 종료 코드 1, JSON 미생성, 타임아웃, 중단, DB 단절 시 실행 중지,
입력 해시/경로 검사, partial/failed 판정. 실제 자식 프로세스로 종료 경로 테스트.
DB 쓰기는 mock이며 실제 PostgreSQL 잠금 경쟁/복구와 Docker 검사 실행은 현장에서 확인해야 합니다.
기존 업로드 API 테스트와 함께 실행:

```bash
python -m pip install -r backend/requirements.txt -r worker/requirements.txt pytest httpx
PYTHONPATH=backend python -m pytest backend/tests worker/tests -q
```

문제 확인: `docker compose logs --tail=100 worker`. 결과 폴더 PermissionError는
호스트 results 폴더 소유자와 worker UID 1000의 쓰기 권한을 확인합니다.
기존 파일 전체 권한 변경이나 볼륨 삭제를 해결책으로 사용하지 않습니다.
