FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LAB_DATA_DIR=/data \
    PORT=8080

WORKDIR /app
COPY . /app/

RUN addgroup --system lab \
    && adduser --system --ingroup lab lab \
    && mkdir -p /data \
    && chown -R lab:lab /data /app

USER lab
EXPOSE 8080
CMD ["python", "/app/app.py"]
