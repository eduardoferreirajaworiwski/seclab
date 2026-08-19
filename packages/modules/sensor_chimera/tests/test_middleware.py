from seclab_sensor_chimera.middleware import RequestSizeLimitMiddleware
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient


async def echo(request):
    body = await request.body()
    return PlainTextResponse(f"received {len(body)} bytes")


def build_app(max_bytes: int) -> Starlette:
    app = Starlette(routes=[Route("/", echo, methods=["POST"])])
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=max_bytes)
    return app


def test_body_within_limit_passes_through():
    client = TestClient(build_app(max_bytes=100))
    response = client.post("/", content=b"x" * 50)
    assert response.status_code == 200
    assert "50 bytes" in response.text


def test_body_over_limit_is_rejected_regardless_of_content_length_header():
    client = TestClient(build_app(max_bytes=10))
    response = client.post("/", content=b"x" * 1000)
    assert response.status_code == 413
