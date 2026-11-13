# SereS as a container. The data (database, profile pictures, attachments)
# lives in the volume /data, the settings come from .env (see .env.example).
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY src/ src/

# Doesn't run as root. UID 1000 so files in ./data belong to the usual first
# user on the host.
RUN useradd --system --uid 1000 --home /data seres && mkdir -p /data && chown seres /data
USER seres
WORKDIR /app/src/backend

# GUNICORN_CMD_ARGS can be changed in .env, e.g. to also listen on [::1].
ENV SERES_DATA_DIR=/data \
    PYTHONUNBUFFERED=1 \
    GUNICORN_CMD_ARGS="--bind=127.0.0.1:2222 --workers=4"

EXPOSE 2222
# --preload: the database is migrated once before the workers start.
CMD ["gunicorn", "--preload", "--no-control-socket", "app:app"]
