"""
ULPF REST API application factory.

    uvicorn ulpf.api.app:app --host 0.0.0.0 --port 8000
    python -m ulpf.main serve --port 8000
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ulpf import __version__
from ulpf.api.routes import get_plugin, public_router, router, shutdown_plugin


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    get_plugin()          # open the store / load parsers before the first request
    yield
    shutdown_plugin()     # drain the listener, flush and close the store


def create_app(console: bool = True) -> FastAPI:
    app = FastAPI(
        title="ULPF — Universal Log Pre-processing Framework",
        description="Security log ingestion, parsing, normalisation and analytics API. "
                    "Set ULPF_API_KEY to require an X-API-Key header.",
        version=__version__,
        lifespan=_lifespan,
    )
    app.include_router(public_router)
    app.include_router(router)
    if console:          # standalone API (ulpf serve): the web console without runtime-only features
        from ulpf.console.server import mount_console
        mount_console(app, None)

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    frontend_dir = os.path.join(project_root, "frontend")
    if os.path.isdir(frontend_dir):
        from fastapi.responses import RedirectResponse
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=frontend_dir, html=True), name="static")

        @app.get("/", include_in_schema=False)
        def _root():
            return RedirectResponse(url="/static/index.html")
    return app


app = create_app()
