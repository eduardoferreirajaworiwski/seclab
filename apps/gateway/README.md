# seclab-gateway

The unified FastAPI gateway: one process mounting every internal module
under versioned routes (`/api/v1/<module>`), replacing the four separate
`main.py`/`chimera_listener.py` entrypoints the original tools each had.

Run: `uvicorn seclab_gateway.main:app --reload` (from this package, with the
workspace venv active), or via the root `docker-compose.yml`.

**The honeypot sensor (`sensor_chimera`) is intentionally not mounted
here** - see its own README for why it stays a separately deployable
process instead of joining this gateway.
