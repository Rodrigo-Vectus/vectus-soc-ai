# Vectus SOC Engine — Fase 1
FROM python:3.10-slim

# Usuario sin privilegios para correr el servicio
RUN useradd --create-home --shell /usr/sbin/nologin vectus

WORKDIR /opt/vectus

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Directorio de datos (SQLite; ChromaDB se suma en Fase 2). Volumen en compose.
RUN mkdir -p /data && chown -R vectus:vectus /data /opt/vectus
USER vectus

EXPOSE 8003

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
