\set ON_ERROR_STOP on
-- v2.1: AI 설명 저장 구조. v2 스키마 위에 추가로 적용하는 마이그레이션.
-- 기존 DB:   docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < db/oss_closeup_v2_1_ai_analysis.sql
-- 이미 적용된 DB에 다시 실행하면 오류로 멈추고 전체가 롤백된다(중복 적용 방지).
--
-- 원칙
--  - LLM은 설명만 만든다. 심각도·우선순위·수정 후보 같은 검사 사실은 이 테이블에 다시 저장하지 않는다.
--  - 설명 생성 실패는 검사 결과 조회를 막지 않는다. 행이 없으면 '아직 생성되지 않음'이다.
--  - 생성 후 검증(입력에 없는 패키지·권고·버전, 시스템 순서와 다른 순서)을 통과하지 못하면 rejected로 남기고 본문을 보여주지 않는다.
BEGIN;

CREATE TABLE ai_analyses (
    analysis_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    -- scan_report: 검사 한 건의 전체 보고서 / finding: 카드별 설명
    scope TEXT NOT NULL CHECK (scope IN ('scan_report', 'finding')),
    finding_id UUID,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'rejected')),
    attempt_no INTEGER NOT NULL DEFAULT 1 CHECK (attempt_no > 0),
    provider TEXT,
    model TEXT,
    prompt_version TEXT NOT NULL CHECK (btrim(prompt_version) <> ''),
    -- 설명에 넣은 사실 묶음의 해시. 결과가 바뀌었는데 예전 설명을 보여주는 일을 막는 데 쓴다.
    input_fingerprint TEXT NOT NULL CHECK (input_fingerprint ~ '^[0-9a-f]{64}$'),
    input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(input_snapshot) = 'object'),
    -- 구조화된 설명 본문(예: summary, why_first, next_checks, uncertainty)
    output JSONB CHECK (output IS NULL OR jsonb_typeof(output) = 'object'),
    -- 생성 후 검증 결과(검사 항목별 통과 여부와 위반 내용)
    validation JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(validation) = 'object'),
    error_code TEXT,
    error_message TEXT,
    usage JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(usage) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    CONSTRAINT ai_scope_target CHECK ((scope = 'finding') = (finding_id IS NOT NULL)),
    CONSTRAINT ai_succeeded_has_output CHECK (status <> 'succeeded' OR output IS NOT NULL),
    CONSTRAINT ai_failure_has_code CHECK (status NOT IN ('failed', 'rejected') OR error_code IS NOT NULL),
    CONSTRAINT ai_time_order CHECK (
        (started_at IS NULL OR started_at >= created_at) AND
        (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at))
    ),
    FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, finding_id) ON DELETE CASCADE
);

-- 같은 대상·같은 프롬프트 버전에서 시도 번호가 겹치지 않게 한다. scan_report는 finding_id가 없으므로 상수로 대체.
CREATE UNIQUE INDEX idx_ai_attempt_unique ON ai_analyses (
    scan_id, scope, COALESCE(finding_id, '00000000-0000-0000-0000-000000000000'::uuid), prompt_version, attempt_no
);
CREATE INDEX idx_ai_latest ON ai_analyses (scan_id, scope, finding_id, created_at DESC);

COMMENT ON TABLE ai_analyses IS
    'LLM explanations only. Facts (severity, priority, fixed versions, scan status) stay in their own tables and are never overwritten here.';
COMMENT ON COLUMN ai_analyses.status IS
    'pending/running/succeeded/failed/rejected. rejected = generated text failed post-generation validation and must not be shown.';

COMMIT;
