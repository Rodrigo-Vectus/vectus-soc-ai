FROM python:3.10-slim
WORKDIR /app
COPY requirements_docker.txt .
RUN pip install --no-cache-dir -r requirements_docker.txt
COPY . .
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8005"]
