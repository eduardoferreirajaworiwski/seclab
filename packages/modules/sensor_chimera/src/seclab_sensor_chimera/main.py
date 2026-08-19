import logging

import uvicorn

from seclab_sensor_chimera.app import app, chimera_settings

logger = logging.getLogger("seclab.sensor_chimera")


def run() -> None:
    logger.info(
        "sensor_chimera_starting",
        extra={"version": chimera_settings.version, "port": chimera_settings.port},
    )
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 (intentional: this sensor is meant to be internet-facing)
        port=chimera_settings.port,
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    run()
