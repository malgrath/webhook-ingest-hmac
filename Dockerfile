# Multi-stage: deps cached on the pyproject/lock layer, app layered last.
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home --shell /usr/sbin/nologin appuser
COPY --from=builder /install /usr/local
COPY --from=builder /build/src ./src
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "webhook_ingest.app:app", "--host", "0.0.0.0", "--port", "8000"]
