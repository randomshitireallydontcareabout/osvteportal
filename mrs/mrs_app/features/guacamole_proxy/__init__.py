"""Flask reverse proxy for a locally hosted Apache Guacamole service."""
from .routes import register

__all__ = ["register"]
