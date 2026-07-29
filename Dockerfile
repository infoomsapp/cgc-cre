# ------------------------------------------------------
# STAGE 1: Backend Runtime (Python + FastAPI)
# ------------------------------------------------------
FROM python:3.11-slim AS backend

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Crear usuario no-root
RUN adduser --system --no-create-home appuser

WORKDIR /app

# Dependencias del sistema mínimas
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements any installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend CGC CORE
COPY app/ ./app/
# Si tienes otros paquetes, añádelos aquí:
# COPY discipleai_legal/ ./discipleai_legal/

# Directorios de runtime
RUN mkdir -p /app/data /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

# Healthcheck hacia tu endpoint real
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Comando: levantar FastAPI con Uvicorn
# Ajusta el módulo según dónde esté tu app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
