# ---------- 1) 검사 도구 다운로드 + 체크섬 검증 ----------
FROM debian:bookworm-slim AS tools
ARG TARGETARCH
ARG TRIVY_VERSION=0.74.0
ARG OSV_VERSION=2.5.1
ARG SYFT_VERSION=1.51.1

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# 공급망 보안 프로젝트답게: 공식 릴리스의 SHA-256을 고정해두고, 다르면 빌드 실패
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) T_ARCH=Linux-64bit;  T_SHA=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a; \
             O_ARCH=linux_amd64;  O_SHA=f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be; \
             S_ARCH=linux_amd64;  S_SHA=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3 ;; \
      arm64) T_ARCH=Linux-ARM64;  T_SHA=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5; \
             O_ARCH=linux_arm64;  O_SHA=3d0f5aa5a6baa8eb32bcef247388e149ef6030a6634ccae6fa0d62681fb27a6d; \
             S_ARCH=linux_arm64;  S_SHA=a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f ;; \
      *) echo "지원하지 않는 아키텍처: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${T_ARCH}.tar.gz"; \
    echo "${T_SHA}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz trivy; \
    curl -fsSLo osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${O_ARCH}"; \
    echo "${O_SHA}  osv-scanner" | sha256sum -c -; \
    curl -fsSLo syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${S_ARCH}.tar.gz"; \
    echo "${S_SHA}  syft.tgz" | sha256sum -c -; \
    tar -xzf syft.tgz syft; \
    install -m 0755 trivy osv-scanner syft /usr/local/bin/

# ---------- 2) 실제 worker 이미지 ----------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/cache/trivy
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/osv-scanner /usr/local/bin/syft /usr/local/bin/

WORKDIR /app
COPY app ./app
COPY run_sample_scan.sh ./run_sample_scan.sh

# root가 아닌 사용자. uid 1000 = WSL/리눅스 기본 사용자와 같게 해서 results 폴더 쓰기 권한 문제 방지
RUN useradd --create-home --uid 1000 worker \
 && mkdir -p /cache/trivy /work/results \
 && chown -R worker:worker /cache /work \
 && chmod +x /app/run_sample_scan.sh
USER worker

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD trivy --version >/dev/null && osv-scanner --version >/dev/null && syft version >/dev/null

CMD ["python", "-m", "app.main"]
