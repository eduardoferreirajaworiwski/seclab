"""Process-wide slowapi Limiter singleton (same singleton pattern as
`get_event_bus`/`get_scheduler`). Lets both the gateway and any module
share one Limiter instance so a module can declare its own per-route
`@limiter.limit(...)` decorator without needing the gateway's `app`
object (slowapi's decorator reads `request.app.state.limiter` by
default, and every module here mounts under the same gateway `app`)."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.wrappers import LimitGroup

_limiter: Limiter | None = None


def get_limiter(default_limits: list[str] | None = None) -> Limiter:
    global _limiter
    if _limiter is None:
        _limiter = Limiter(key_func=get_remote_address, default_limits=default_limits or [])
    elif default_limits is not None:
        # A module (e.g. phantom.routes) may import this before the gateway
        # sets its process-wide default - apply the caller-supplied default
        # onto the already-created singleton rather than silently ignoring it.
        # Must be wrapped as LimitGroup objects, mirroring Limiter.__init__.
        _limiter._default_limits = [
            LimitGroup(limit, _limiter._key_func, None, False, None, None, None, 1, False)
            for limit in set(default_limits)
        ]
    return _limiter
