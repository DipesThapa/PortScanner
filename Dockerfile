# Stage 1: Build Frontend
FROM node:18-slim AS frontend-builder
WORKDIR /app/frontend
COPY webapp/frontend/package*.json ./
RUN npm install
COPY webapp/frontend/ ./
RUN npm run build

# Stage 2: Final Backend Image
FROM python:3.11-slim

# Install system dependencies (nmap + libcap for setcap)
RUN apt-get update && apt-get install -y --no-install-recommends nmap libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY portscanner /app/portscanner
COPY webapp /app/webapp

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /app/frontend/dist /app/webapp/frontend/dist

# Create runtime state dir and drop root privileges.
# Note: nmap loses raw-socket capability as non-root, so -A/SYN scans fall back
# to TCP connect scans. Grant cap_net_raw to the nmap binary if raw scans are
# required, rather than running the whole service as root.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || true \
    && mkdir -p /app/web_runs \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Basic container healthcheck against the unauthenticated endpoint.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)" || exit 1

# Command to run the application
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]
