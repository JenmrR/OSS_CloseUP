import { useEffect, useState } from 'react'
import { getAiReport } from './api'
import { aiReportView } from './display'

// 전체 AI 보고서 자리. 설명 조회가 실패해도 검사 결과 화면은 막지 않는다.
// 기본 펼침 + 접기. 본문 구조(요약·먼저 볼 항목·다음 행동)는 LLM 연동 때 채운다.
export default function AiReport({ scanId, scanStatus }) {
  // 응답을 요청 키와 함께 저장하고, 키가 다르면(새 요청 중) 불러오는 중으로 본다.
  // effect 안에서 상태를 바로 바꾸지 않아 불필요한 다시 그리기를 피한다.
  const requestKey = `${scanId}:${scanStatus}`
  const [result, setResult] = useState({ key: null })
  const [open, setOpen] = useState(true)

  useEffect(() => {
    if (!scanId) return undefined
    let cancelled = false
    getAiReport(scanId)
      .then((data) => { if (!cancelled) setResult({ key: requestKey, data }) })
      .catch((error) => { if (!cancelled) setResult({ key: requestKey, error }) })
    return () => { cancelled = true }
  }, [scanId, requestKey])

  const view = aiReportView(result.key === requestKey ? result : { loading: true })
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
