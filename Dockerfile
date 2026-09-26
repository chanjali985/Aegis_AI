FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home aegis
WORKDIR /app
COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir .

USER aegis
ENV AEGIS_DATA_DIR=/data PYTHONUNBUFFERED=1
RUN git config --global user.email "aegis@acme.dev" && git config --global user.name "AegisAI"
EXPOSE 8000
CMD ["aegis", "serve", "--host", "0.0.0.0", "--port", "8000"]
