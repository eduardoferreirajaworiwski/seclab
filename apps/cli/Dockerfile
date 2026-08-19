FROM python:3.11-slim

RUN useradd -m seclab_user

WORKDIR /app

# Build context is the monorepo root (see ../../docker-compose.yml). This
# image is reused for: one-off CLI commands (`users create`, `phantom
# analyze`) and the long-running `monitor run` CertStream listener service.
COPY packages/seclab-core /build/seclab-core
COPY packages/modules/phantom /build/phantom
COPY packages/modules/recon /build/recon
COPY packages/modules/monitor /build/monitor
COPY apps/cli /build/cli

RUN pip install --no-cache-dir \
    /build/seclab-core \
    /build/phantom \
    /build/recon \
    /build/monitor \
    /build/cli

RUN mkdir -p /data && chown -R seclab_user:seclab_user /app /data
USER seclab_user

ENTRYPOINT ["seclab"]
CMD ["--help"]
