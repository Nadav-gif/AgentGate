"""FastAPI application factory for the AgentGate proxy."""

from __future__ import annotations

from fastapi import FastAPI

from agentgate.proxy.dependencies import AppDependencies, init_dependencies
from agentgate.proxy.routes import router


def create_app(deps: AppDependencies) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        deps: all shared dependencies (authenticator, config, registry, fetcher, audit).

    Returns:
        A configured FastAPI app ready to serve requests.
    """
    app = FastAPI(
        title="AgentGate",
        description="Runtime permission enforcement proxy for AI agents accessing AWS services",
        version="0.1.0",
    )

    init_dependencies(deps)
    app.include_router(router)

    return app
