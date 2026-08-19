FROM python:3.11-slim

RUN useradd -m seclab_user

WORKDIR /app

# Build context is the monorepo root (see ../../docker-compose.yml): the
# gateway pulls in seclab-core plus every internal module it mounts.
COPY packages/seclab-core /build/seclab-core
COPY packages/modules/phantom /build/phantom
COPY packages/modules/recon /build/recon
COPY packages/modules/monitor /build/monitor
COPY apps/gateway /build/gateway

RUN pip install --no-cache-dir \
    /build/seclab-core \
    /build/phantom \
    /build/recon \
    /build/monitor \
    /build/gateway

RUN mkdir -p /data && chown -R seclab_user:seclab_user /app /data
USER seclab_user

EXPOSE 8000

CMD ["uvicorn", "seclab_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
