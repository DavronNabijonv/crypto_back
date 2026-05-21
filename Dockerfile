# ---- builder stage ----
FROM python:3.13-slim AS builder

WORKDIR /app
COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- runtime stage ----
FROM python:3.13-slim AS runtime

# Non-root user — home set to /app so gunicorn's control socket has a writable dir
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source only (venv, __pycache__, .git excluded via .dockerignore)
COPY . .

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

# PORT is injected by Render at runtime. WORKERS can be overridden via env var.
CMD ["sh", "-c", "gunicorn main:app \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:${PORT:-8000} \
  --workers ${WORKERS:-2} \
  --timeout 60 \
  --access-logfile - \
  --error-logfile -"]
