# Multi-stage build for compliance-assess.
# Stage 1: builder. Resolves dependencies and produces a wheel.
# Stage 2: runtime. Slim image with the wheel installed; entrypoint = compliance-assess.

# TODO(P0-08): pin to digest — FROM python:3.11-slim-bookworm@sha256:<digest> AS builder
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --upgrade pip build \
    && python -m build --wheel --outdir /dist


# TODO(P0-08): pin to digest — FROM python:3.11-slim-bookworm@sha256:<digest> AS runtime
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:${PATH}"

# semgrep runtime requirement: a libc-compatible Python; the OCaml binary is bundled by the wheel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

COPY --from=builder /dist/*.whl /tmp/
# A-M7: TODO(P0-08): add docker/requirements-hashed.txt with --require-hashes once
# semgrep==1.95.0 and compliance-assess are published to PyPI and hashes are generated via:
#   pip download --no-deps semgrep==1.95.0 && pip hash <wheel>
# Until then the version pin is the strongest available defence without PyPI access.
RUN /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install /tmp/*.whl "semgrep==1.95.0" \
    && rm /tmp/*.whl

# Non-root user. compliance-assess only needs read access to the target directory and write
# access to the output directory; both are bind-mounted at runtime.
RUN useradd --create-home --shell /bin/bash --uid 10001 assessor
USER assessor
WORKDIR /workspace

LABEL org.opencontainers.image.title="compliance-assess" \
      org.opencontainers.image.description="Compliance gap-finder for CA/US/EU privacy and AI-governance regulations" \
      org.opencontainers.image.source="https://github.com/arkoinc-ca/compliance-assess" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Arkoinc Inc."

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD compliance-assess --version || exit 1

ENTRYPOINT ["compliance-assess"]
CMD ["--help"]
