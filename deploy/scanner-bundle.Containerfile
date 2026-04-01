FROM --platform=linux/amd64 golang:1.25-bookworm AS go-toolchain
FROM --platform=linux/amd64 aquasec/trivy:0.69.1 AS trivy-binary
FROM --platform=linux/amd64 curlimages/curl:8.12.1 AS asset-fetcher

ARG GITLEAKS_VERSION=8.24.2
ARG SYFT_VERSION=1.22.0
ARG OSV_SCANNER_VERSION=2.2.2
ARG NUCLEI_VERSION=3.4.10

USER root
WORKDIR /downloads

RUN curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o gitleaks.tar.gz

RUN curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    -o syft.tar.gz

RUN curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    -o osv-scanner \
 && chmod +x osv-scanner

RUN curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o nuclei.zip

FROM --platform=linux/amd64 debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

ARG SEMGREP_VERSION=1.119.0
ARG GITLEAKS_VERSION=8.24.2
ARG TRIVY_VERSION=0.69.1
ARG SYFT_VERSION=1.22.0
ARG OSV_SCANNER_VERSION=2.2.2
ARG CHECKOV_VERSION=3.2.489
ARG CLAMAV_VERSION=1.4.3
ARG STATICCHECK_VERSION=2025.1.1
ARG GOVULNCHECK_VERSION=1.1.4
ARG CODEQL_VERSION=2.23.3
ARG KNIP_VERSION=5.70.1
ARG VULTURE_VERSION=2.14
ARG NUCLEI_VERSION=3.4.10
ARG ZAP_VERSION=2.16.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    clamav \
    curl \
    git \
    jq \
    npm \
    openjdk-17-jre-headless \
    python3 \
    python3-pip \
    tar \
    unzip \
  && rm -rf /var/lib/apt/lists/*

COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=trivy-binary /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=asset-fetcher /downloads/gitleaks.tar.gz /tmp/gitleaks.tar.gz
COPY --from=asset-fetcher /downloads/syft.tar.gz /tmp/syft.tar.gz
COPY --from=asset-fetcher /downloads/osv-scanner /tmp/osv-scanner
COPY --from=asset-fetcher /downloads/nuclei.zip /tmp/nuclei.zip

ENV PATH="/root/.local/bin:/usr/local/go/bin:/usr/local/bin:${PATH}"

ENV PIP_DEFAULT_TIMEOUT=300

RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 300 --break-system-packages \
    "setuptools>=82" \
    "semgrep==${SEMGREP_VERSION}" \
    "checkov==${CHECKOV_VERSION}" \
    "vulture==${VULTURE_VERSION}" \
 && npm install -g "knip@${KNIP_VERSION}"

RUN go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" \
 && go install "golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK_VERSION}"

RUN tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tar.gz

RUN tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
 && rm -f /tmp/syft.tar.gz

RUN mv /tmp/osv-scanner /usr/local/bin/osv-scanner \
 && chmod +x /usr/local/bin/osv-scanner

RUN unzip -q /tmp/nuclei.zip -d /tmp/nuclei \
 && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
 && rm -rf /tmp/nuclei /tmp/nuclei.zip

RUN curl -fsSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
    | tar -xz -C /opt \
 && chmod -R a+rX /opt/codeql \
 && ln -sf /opt/codeql/codeql /usr/local/bin/codeql

RUN mkdir -p /opt/zap \
 && curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    | tar -xz -C /opt/zap --strip-components=1 \
 && printf '%s\n' '#!/usr/bin/env bash' 'exec /opt/zap/zap.sh "$@"' > /usr/local/bin/zaproxy \
 && chmod +x /usr/local/bin/zaproxy

RUN freshclam || true

WORKDIR /workspace
ENTRYPOINT ["/bin/bash"]
