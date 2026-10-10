import { useEffect, useState } from 'react'
import { getAiReport } from './api'
import { aiReportView } from './display'

// 전체 AI 보고서 자리. 설명 조회가 실패해도 검사 결과 화면은 막지 않는다.
// 기본 펼침 + 접기. 본문 구조(요약·먼저 볼 항목·다음 행동)는 LLM 연동 때 채운다.
export default function AiReport({ scanId, scanStatus }) {
  const [state, setState] = useState({ loading: true })
  const [open, setOpen] = useState(true)

  useEffect(() => {
    if (!scanId) return undefined
    let cancelled = false
    setState({ loading: true })
    getAiReport(scanId)
      .then((data) => { if (!cancelled) setState({ data }) })
      .catch((error) => { if (!cancelled) setState({ error }) })
    return () => { cancelled = true }
  }, [scanId, scanStatus])

  const view = aiReportView(state)
  return (
    <section className="card">
      <div className="card-head">
        <h2>AI 요약 보고서</h2>
        <button type="button" className="link" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? '접기 ▴' : '펼치기 ▾'}
        </button>
      </div>
      {open && (
        <>
          <p className={view.tone === 'error' ? 'error-text' : 'muted'}>{view.message}</p>
          {view.output && (
            <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(view.output, null, 2)}</pre>
          )}
          {view.meta && <p className="hint">{view.meta}</p>}
          <p className="hint">
            순서·심각도·버전·검사 상태는 검사 시스템 값이며, AI는 설명 문장만 작성합니다.
            설명이 없어도 아래 검사 결과는 그대로 확인할 수 있습니다.
          </p>
        </>
      )}
    </section>
  )
}
