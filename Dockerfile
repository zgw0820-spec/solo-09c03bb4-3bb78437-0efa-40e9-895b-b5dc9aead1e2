FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY keys ./keys

RUN useradd --system --uid 10001 --home-dir /srv appuser \
    && chown -R appuser:appuser /srv
USER appuser

# 5353/udp = authoritative DNS, 8000/tcp = FastAPI / Swagger UI
EXPOSE 5353/udp 8000/tcp

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
