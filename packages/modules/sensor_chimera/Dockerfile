FROM python:3.11-slim

RUN useradd -m chimera_user

WORKDIR /app

# seclab-core isn't published anywhere - it must be built into the image
# alongside the sensor itself (build context is the monorepo root; see the
# workspace docker-compose.yml).
COPY packages/seclab-core /build/seclab-core
COPY packages/modules/sensor_chimera /build/sensor_chimera

RUN pip install --no-cache-dir /build/seclab-core /build/sensor_chimera

RUN chown -R chimera_user:chimera_user /app
USER chimera_user

EXPOSE 8000

CMD ["python", "-m", "seclab_sensor_chimera.main"]
