"""Permission proxy — FastAPI layer that ties all components together."""

from agentgate.proxy.app import create_app

__all__ = ["create_app"]
