# AI 요약·개별 설명 분리

기존 week3 UI와 week4-ai-integration.patch 적용 상태에 추가하는 패치입니다.
DB 초기화나 스키마 변경은 없습니다.

## 변경 사항

- 전체 요약: 긴 개별 설명 대신 그룹별 건수, 대표 패키지, 확인할 행동을 표시합니다.
- 저장된 P0 → P1 → P2 → P3 → INFO 순서로 표시합니다. 우선순위가 없는 항목은 심각도별 '산정 대기' 그룹으로 분리하며 P 등급을 추정하지 않습니다.
- UNKNOWN, 라이선스, 유지보수는 별도 그룹입니다. 라이선스·유지보수 그룹은 findings에 해당 유형이 저장된 경우에 표시됩니다.
- 그룹의 취약점 목록은 기본으로 접혀 있습니다. 목록에서 항목을 선택하면 상세 화면으로 이동합니다.
- 개별 AI 설명은 취약점 상세의 'AI 설명 생성'으로 생성하며 finding 범위로 따로 저장·조회합니다. 화면 열기만으로 유료 호출하지 않습니다.
- 기존 scan-evidence-v1 보고서는 숨기고 새 형식으로 다시 생성하도록 안내합니다. 새 생성은 유료 호출일 수 있습니다.
- 전체 집계는 30개에서 잘라내지 않습니다. 패키지 연결 20,000개를 넘으면 부분 결과를 전체처럼 표시하지 않고 명시적으로 생성 한도를 알립니다. 개별 설명은 한 취약점의 연결 패키지 30개까지 지원합니다.
- AI는 근거에 맞는 설명 코드를 선택하고 서버가 검증된 한국어 문장으로 표시하는 기존 방식을 유지합니다.

## 정민 님 우선순위 모듈 연결 계약

우선순위 계산은 이 코드에 포함하지 않습니다. 모듈의 결과를 기존 finding_packages 테이블에 저장하면 읽을 수 있는 구조입니다.

| 대상 | 필드 | 계약 |
| --- | --- | --- |
| 검사·취약점·패키지 연결 | scan_id, finding_id, package_id | 기존 연결 행을 식별 |
| 우선순위 | priority | P0/P1/P2/P3/INFO 또는 NULL |
| 계산 규칙 버전 | priority_rule_version | 사용한 규칙 버전 |

모듈의 최종 출력 형태가 다르면 저장 연결부에서 이 계약에 맞춰야 합니다. 모듈 파일을 올리는 것만으로 DB 값이 자동 채워지지는 않습니다.
API의 findings 응답은 이미 packages[].priority를 제공하며 그룹 목록도 같은 값을 사용합니다.
값이 변경되면 페이지를 새로고침하고 AI 보고서를 다시 생성해야 새 그룹이 저장됩니다. 입력 해시가 변경된 이전 결과는 오래된 결과로 처리합니다.
같은 취약점이 패키지마다 다른 우선순위를 가지면 여러 그룹에 속할 수 있습니다. 전체 건수는 고유 finding 수, 각 그룹 건수는 해당 그룹의 고유 finding 수입니다.

## 적용

패치를 WSL의 ~/oss-closeup 폴더에 복사한 뒤 실행합니다. 기존 venv가 준비되어 있는 상태를 기준으로 합니다.

```bash
cd ~/oss-closeup &&
git apply --check ./week4-ai-report-layout.patch &&
git apply ./week4-ai-report-layout.patch &&
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests/test_ai_analysis.py -q &&
.venv/bin/python -m unittest discover -s backend/tests -p 'test_ai_generation.py' -v &&
.venv/bin/python -m unittest discover -s backend/tests -p 'test_ai_groups.py' -v &&
.venv/bin/python -m unittest discover -s backend/tests -p 'test_ai_service.py' -v &&
cd frontend &&
node --test tests/*.test.js &&
npx oxlint src &&
npm run build
```

성공하면 백엔드 코드를 새로 빌드하고 API 설정을 다시 전달합니다.

```bash
cd ~/oss-closeup && bash scripts/enable-ai.sh backend
```

기존 모델 ID와 API 키를 입력합니다. 키는 채팅이나 코드에 붙이지 않습니다.
기존 프론트 개발 서버가 실행 중이면 브라우저를 새로고침합니다. 꺼져 있다면 다음 명령으로 실행합니다.

```bash
cd ~/oss-closeup/frontend && npm run dev
```

## 확인

1. 완료/부분 완료된 기존 검사에서 요약 보고서를 다시 생성합니다.
2. UUID가 붙은 긴 설명 목록 대신 그룹 카드가 보이는지 확인합니다.
3. 그룹의 취약점 목록을 열고 상세로 이동합니다.
4. 상세의 AI 설명 생성을 눌러 해당 취약점 설명만 나오는지 확인합니다.
5. 새로고침해 두 설명이 각각 유지되는지 확인합니다.

로컬 확인: Python 단위 테스트 32개(모의 DB 포함), 프론트 단위 테스트 8개, JS/JSX 구문 분석 및 패치 적용 검증.
전달받은 소스 묶음에는 전체 테스트·프론트 의존성이 없어 전체 React 빌드, 실제 PostgreSQL·유료 API 동작은 이 환경에서 실행하지 못했습니다. 위 명령으로 사용자 환경에서 확인합니다.

이전 검사와의 연관 분석은 이번 패치 범위에 포함하지 않으며 이후 확장합니다.
