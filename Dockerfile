FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Directorios para SQLite local y logs
RUN mkdir -p /app/data /app/logs

EXPOSE 8000

# Se evalúa $PORT correctamente antes de ejecutar uvicorn
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port $PORT"]