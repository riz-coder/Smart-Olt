FROM python:3.13-slim AS runtime

ARG VERSION=development

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=oltportal.settings

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential libxml2-dev libxslt1-dev zlib1g-dev \
       wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
RUN printf '%s' "$VERSION" > /app/VERSION \
    && chmod 0755 /app/docker/entrypoint.sh \
    && DJANGO_SECRET_KEY=container-build-only \
       DJANGO_DEBUG=False \
       DB_ENGINE=postgresql \
       DB_NAME=collectstatic \
       DB_USER=collectstatic \
       DB_PASSWORD=collectstatic \
       python manage.py collectstatic --noinput \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin optiverse \
    && mkdir -p /runtime /app/media /etc/optiverse/wg /run/optiverse \
    && chown -R 1000:1000 /runtime /app/media /etc/optiverse/wg /run/optiverse

USER 1000:1000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["gunicorn", "oltportal.asgi:application", "--bind", "0.0.0.0:8000", "--workers", "1", "--worker-class", "uvicorn.workers.UvicornWorker", "--timeout", "180", "--graceful-timeout", "30", "--keep-alive", "5", "--max-requests", "2000", "--max-requests-jitter", "200", "--access-logfile", "-", "--error-logfile", "-"]
