# seclab-sensor-chimera

Active-deception honeypot sensor, ported from the standalone `project-chimera`
into the `seclab` monorepo. Pretends to be a real production app; when
probed, fingerprints the request, tarpits automated scanners, serves decoy
secrets, and emits the hit to the shared `seclab.core.events` bus.

**Deployed separately from the gateway, deliberately.** A honeypot lives in
a different trust zone than the internal analysis/workflow apps - it is
internet-facing by design and must never hold credentials to the main lab
database. It only depends on `seclab.core` (config, logging, hardened HTTP
client, event bus), never on `seclab.core.db` or `seclab.security`.

Run standalone: `python -m seclab_sensor_chimera.main` or via the module's
own `Dockerfile` / the workspace `docker-compose.yml`'s `sensor-chimera`
service (on its own network, not sharing the gateway's).

## Fixes applied during migration (vs. the original project-chimera)

- `send_discord_alert` is now wrapped by `seclab.core.events.DiscordSink`,
  which already catches and logs webhook failures - the original had no
  try/except and a webhook outage could 500 the request handler.
- GeoIP lookups moved to HTTPS, go through the shared egress-checked HTTP
  client, and are cached in-memory per IP for a few minutes instead of
  firing on every single hit.
- Request-size limiting no longer trusts the `Content-Length` header alone;
  the body stream itself is capped, so a spoofed/missing header can't bypass
  the limit.
- A single `Settings.version` replaces the hardcoded, inconsistent
  `2.0.0-stable` (README) vs. `Chimera Intel v3.0` (code) strings.
