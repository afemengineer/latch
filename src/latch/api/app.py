"""FastAPI control plane for the local Latch demonstration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.responses import Response

from latch.api.demo import DemoController, DemoMode
from latch.api.ui import DEMO_HTML
from latch.core.types import DataLabel


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResetRequest(_StrictModel):
    mode: DemoMode | None = None


class TaskRequest(_StrictModel):
    request: str = Field(min_length=1, max_length=6000)
    label: DataLabel = DataLabel.PUBLIC


class RunRequest(_StrictModel):
    max_steps: int = Field(default=8, ge=1, le=16)


class ApprovalRequest(_StrictModel):
    approved_by: str = Field(default="local-user", min_length=1, max_length=128)
    persist: bool = False


class DenialRequest(_StrictModel):
    denied_by: str = Field(default="local-user", min_length=1, max_length=128)


class LiveConfigRequest(_StrictModel):
    nebius_api_key: SecretStr
    tavily_api_key: SecretStr
    nebius_base_url: str = Field(min_length=8, max_length=500)
    nebius_model: str = Field(min_length=1, max_length=300)
    force_adversarial_model: bool = True


def create_app(controller: DemoController | None = None) -> FastAPI:
    """Create the loopback-oriented single-user demo app."""

    demo = controller or DemoController()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        demo.close()

    app = FastAPI(
        title="Latch Demo",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(DEMO_HTML)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/state")
    def state() -> dict[str, object]:
        return demo.state()

    @app.post("/api/demo/reset")
    def reset(request: ResetRequest) -> dict[str, object]:
        try:
            demo.reset(request.mode)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/live/configure")
    def configure_live(request: LiveConfigRequest) -> dict[str, object]:
        nebius_key = request.nebius_api_key.get_secret_value()
        tavily_key = request.tavily_api_key.get_secret_value()
        try:
            demo.configure_live(
                nebius_api_key=nebius_key,
                tavily_api_key=tavily_key,
                nebius_base_url=request.nebius_base_url,
                nebius_model=request.nebius_model,
                force_adversarial_model=request.force_adversarial_model,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/task")
    def create_task(request: TaskRequest) -> dict[str, object]:
        try:
            demo.start_task(request=request.request, label=request.label)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/task/step")
    def step_task() -> dict[str, object]:
        try:
            demo.step()
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/task/run")
    def run_task(request: RunRequest) -> dict[str, object]:
        try:
            demo.run(max_steps=request.max_steps)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/task/approve")
    def approve_task(request: ApprovalRequest) -> dict[str, object]:
        try:
            demo.approve(
                approved_by=request.approved_by,
                persist=request.persist,
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    @app.post("/api/task/deny")
    def deny_task(request: DenialRequest) -> dict[str, object]:
        try:
            demo.deny(denied_by=request.denied_by)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return demo.state()

    return app
