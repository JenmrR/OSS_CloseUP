// FastAPI 호출 모음. 모든 경로는 vite 프록시를 통해 /api 로 나간다.

const BASE = '/api'

async function request(path, options) {
  const response = await fetch(BASE + path, options)
  const text = await response.text()
  let body = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { detail: text }
    }
  }
  if (!response.ok) {
    const error = new Error(describe(body, response.status))
    error.status = response.status
    error.body = body
    throw error
  }
  return body
}

function describe(body, status) {
  const detail = body && body.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object') return detail.message || JSON.stringify(detail)
  return `요청이 실패했습니다 (HTTP ${status})`
}

export function createScan(packageJson, packageLock) {
  const form = new FormData()
  form.append('package_json', packageJson, 'package.json')
  form.append('package_lock', packageLock, 'package-lock.json')
  return request('/scans', { method: 'POST', body: form })
}

export const getScan = (scanId) => request(`/scans/${scanId}`)
export const getPackages = (scanId) => request(`/scans/${scanId}/packages?limit=500`)
export const getMaintenance = (scanId) => request(`/scans/${scanId}/maintenance?limit=500`)
export const getFindings = (scanId) => request(`/scans/${scanId}/findings?limit=500`)

// SBOM 미생성은 404로 오지만 오류가 아니다. available:false 로 바꿔서 돌려준다.
export async function getSbomInfo(scanId) {
  try {
    return await request(`/scans/${scanId}/sbom/info`)
  } catch (error) {
    if (error.status === 404 && error.body && error.body.detail && error.body.detail.reason) {
      return { available: false, syft: error.body.detail.syft }
    }
    throw error
  }
}

export const sbomDownloadUrl = (scanId) => `${BASE}/scans/${scanId}/sbom`
