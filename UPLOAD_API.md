# 업로드 API (2주차 개발 초안)

전제: db/oss_closeup_v2.sql 적용 완료. 이 변경은 DB를 초기화하지 않습니다.

## 실행

```bash
docker compose up -d --build backend
docker compose up -d --no-deps worker
curl -sS -F 'package_json=@samples/poc77/package.json' \
  -F 'package_lock=@samples/poc77/package-lock.json' http://localhost:8000/scans
```

202 응답: project_id, scan_id, status=queued, status_url.
반환된 scan_id로 `GET /scans/{scan_id}`를 호출합니다. /docs에서도 업로드할 수 있습니다.
worker는 여전히 자리표시이므로 queued가 유지됩니다. 자동 검사는 다음 작업입니다.

## 계약

- multipart 필드: package_json / package_lock. 파일명: package.json / package-lock.json.
- 기본 제한(개발 제안): 각 1 MiB / 10 MiB, 전체 요청은 합계 + 256 KiB.
- UTF-8 JSON 객체, 중복 키·NaN 거부. lockfileVersion 2/3만 지원.
- 루트 이름/버전(존재 시) 및 dependency 선언 일치 확인.
- workspace/로컬 링크 미지원. 완전한 npm 의존성 해석은 검사 모듈의 후속 검증 대상.
- 파일이나 scripts를 실행하지 않고 npm install도 호출하지 않음.
- 422: 파일 누락/이름/JSON/쌍 불일치, 413: 크기 초과, 503: 저장/DB 실패, 404: 없는 검사.
- 같은 업로드를 다시 요청하면 새 검사 생성. HTTP 요청 멱등성은 미구현.

## 저장

backend와 worker는 scan-uploads 볼륨을 /work/uploads에 공유합니다.
backend는 쓰기, worker는 읽기 전용. DB에는 UUID/파일명 형태의 상대 storage_key와
원본 바이트 SHA-256·크기를 저장합니다. project, scan_run, artifacts 2행을 한 트랜잭션으로 저장합니다.
파일을 먼저 완성하고 DB를 커밋하므로 worker는 부분 작성 파일을 읽지 않습니다.

DB 오류/프로세스 중단으로 미참조 파일이 남을 수 있습니다. COMMIT 응답이 끊겨도
서버에서 커밋됐을 수 있어 오류 직후 파일을 무조건 삭제하지 않습니다.
미참조 파일 정리와 검사 종료 후 원본 삭제는 후속 worker/정리 작업에 구현해야 합니다.
보관 기간은 아직 합의 전이며 임의로 자동 삭제하지 않습니다.
로컬 개발 전용(기존 127.0.0.1 바인딩 유지). 인증/사용자 격리/요청 빈도 제한은 포함하지 않습니다.

## 검증

```bash
python -m pip install -r backend/requirements.txt pytest httpx
PYTHONPATH=backend python -m pytest backend/tests -q
```

15개 테스트: 실제 poc77 입력, 정상 응답/파일 원본 보존, 잘못된 JSON·lock·파일명,
누락, 크기 제한, DB 실패, 조회 404/UUID 검증. DB 연결은 mock입니다.
Docker 이미지 빌드 및 실제 PostgreSQL 저장·공유 볼륨 권한은 로컬 실행에서 최종 확인합니다.
테스트 업로드는 실제 행/파일을 남깁니다. 자동으로 기존 데이터나 볼륨을 삭제하지 않습니다.
