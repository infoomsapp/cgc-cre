# 1. Usar imagen base ligera de Python 3.11
FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc en disco y forzar stdout/stderr sin buffer
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 2. Instalar dependencias del sistema necesarias para PostgreSQL y Cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 3. Crear el grupo y el usuario 'appuser' ANTES de usar chown
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 4. Copiar e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copiar todo el código fuente del proyecto
COPY . .

# 6. Crear los directorios de datos/logs y asignar permisos al usuario no-root
RUN mkdir -p /app/data /app/logs && chown -R appuser:appuser /app

# 7. Cambiar al usuario seguro sin privilegios
USER appuser

# 8. Puerto de escucha (Railway usará la variable PORT automáticamente)
EXPOSE 8000

# 9. Comando de arranque de la API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]