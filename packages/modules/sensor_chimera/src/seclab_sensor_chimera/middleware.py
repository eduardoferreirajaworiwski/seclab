from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, server_label: str) -> None:
        super().__init__(app)
        self._server_label = server_label

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Server"] = self._server_label
        return response


class RequestSizeLimitMiddleware:
    """Enforces max_bytes on the *actual* body stream, not just the
    Content-Length header. The original project-chimera implementation
    (chimera_listener.py) only checked the header, which a client can omit
    or lie about (chunked transfer-encoding has no Content-Length at all) to
    smuggle an oversized body past the check.

    Reads and buffers the body up front (capped at max_bytes+1) so it can
    reject before the downstream app ever sees an oversized request, then
    replays the buffered chunks through a substitute `receive`.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        buffered = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            buffered.extend(message.get("body", b""))
            if len(buffered) > self.max_bytes:
                await _send_413(send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(buffered), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


async def _send_413(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"Payload Too Large"})
