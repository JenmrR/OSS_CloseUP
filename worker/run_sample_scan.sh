#!/usr/bin/env bash
# worker 컨테이너 안에서 샘플 lock file을 세 도구로 검사하고 결과를 /work/results 에 저장
# 사용: docker compose exec worker /app/run_sample_scan.sh [lock 파일 경로]
set -u
LOCK="${1:-/work/samples/poc77/package-lock.json}"
OUT="${RESULTS_DIR:-/work/results}/worker_scan"
mkdir -p "$OUT"
echo "입력: $LOCK"
echo "sha256: $(sha256sum "$LOCK" | cut -d' ' -f1)"

# --- Trivy: 취약점이 있어도 종료 코드 0 ---
trivy fs --scanners vuln --format json --output "$OUT/trivy.json" \
  --cache-dir "$TRIVY_CACHE_DIR" --db-repository ghcr.io/aquasecurity/trivy-db:2 \
  --disable-telemetry --skip-version-check --no-progress --timeout 10m "$LOCK" 2> "$OUT/trivy.log"
T_EXIT=$?

# --- OSV-Scanner: 취약점 발견 시 종료 코드 1 (실패 아님) ---
osv-scanner scan source -L "$LOCK" --format json --output-file "$OUT/osv.json" > "$OUT/osv.log" 2>&1
O_EXIT=$?

# --- Syft: SBOM + 라이선스 ---
syft "file:$LOCK" -o "syft-json=$OUT/syft.json" -o "spdx-json=$OUT/sbom.spdx.json" -q 2> "$OUT/syft.log"
S_EXIT=$?

python - "$OUT" "$T_EXIT" "$O_EXIT" "$S_EXIT" << 'PY'
import json, sys, os
out, t_exit, o_exit, s_exit = sys.argv[1], *map(int, sys.argv[2:])

def load(name):
    p = os.path.join(out, name)
    try:
        return json.load(open(p))
    except Exception:
        return None

def verdict(tool, code, data):
    if tool == "osv" and code == 1 and data is not None:
        return "성공 (취약점 발견 → 종료 코드 1은 정상)"
    if code == 0 and data is not None:
        return "성공"
    return "실패 (종료 코드 %d, 로그 확인)" % code

t, o, s = load("trivy.json"), load("osv.json"), load("syft.json")
tn = sum(len(r.get("Vulnerabilities") or []) for r in (t or {}).get("Results", []))
tp = len({(v["PkgName"], v["InstalledVersion"]) for r in (t or {}).get("Results", []) for v in (r.get("Vulnerabilities") or [])})
on = sum(len(p.get("vulnerabilities", [])) for r in (o or {}).get("results", []) for p in r["packages"])
op = sum(1 for r in (o or {}).get("results", []) for p in r["packages"] if p.get("vulnerabilities"))
arts = (s or {}).get("artifacts", [])
lic = sum(1 for a in arts if a.get("licenses"))

print()
print("Trivy : %-40s 패키지 %2d개 / %d건   (정민 로컬: 14개 / 53건)" % (verdict("trivy", t_exit, t), tp, tn))
print("OSV   : %-40s 패키지 %2d개 / %d건   (정민 로컬: 14개 / 52건)" % (verdict("osv", o_exit, o), op, on))
print("Syft  : %-40s 패키지 %2d개 / 라이선스 %d개 (재실행: 77 / 77)" % (verdict("syft", s_exit, s), len(arts), lic))
print("\n결과 폴더:", out, "(PC에서는 ~/oss-closeup/results/worker_scan)")
print("※ 취약점 DB가 계속 갱신되므로 건수가 조금 다를 수 있음")
PY
