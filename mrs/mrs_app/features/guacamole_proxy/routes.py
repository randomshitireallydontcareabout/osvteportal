"""Proxy /guacamole/* through Flask to the local Guacamole container.

This provides HTTP and streaming tunnel proxying without adding a third-party
Python dependency. WebSocket Upgrade requests receive a clear 426 response;
Guacamole can use its HTTP tunnel through this proxy when WebSockets are not
available through the Flask/Werkzeug server.
"""
from __future__ import annotations

import http.client
import os
from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, current_app, request, stream_with_context

bp = Blueprint("guacamole_proxy", __name__)

DEFAULT_UPSTREAM = "http://127.0.0.1:8080"
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


def _upstream():
    raw = os.environ.get("GUACAMOLE_UPSTREAM", DEFAULT_UPSTREAM).strip().rstrip("/")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("GUACAMOLE_UPSTREAM must be an http:// or https:// URL")
    return parsed


def _connection(parsed):
    timeout = float(os.environ.get("GUACAMOLE_PROXY_TIMEOUT", "300"))
    cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    return cls(parsed.hostname, parsed.port, timeout=timeout)


def _target_path(path: str) -> str:
    target = "/guacamole/" + path.lstrip("/")
    if request.query_string:
        target += "?" + request.query_string.decode("latin-1")
    return target


def _forward_headers(parsed):
    headers = {}
    connection_tokens = {
        token.strip().lower()
        for token in request.headers.get("Connection", "").split(",")
        if token.strip()
    }
    blocked = HOP_BY_HOP | connection_tokens | {"host", "content-length"}
    for name, value in request.headers.items():
        if name.lower() not in blocked:
            headers[name] = value
    host = parsed.hostname
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    headers["Host"] = host
    headers["X-Forwarded-For"] = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", request.scheme)
    headers["X-Forwarded-Host"] = request.host
    headers["X-Forwarded-Prefix"] = "/guacamole"
    if request.content_length is not None:
        headers["Content-Length"] = str(request.content_length)
    return headers


def _response_headers(upstream_response):
    connection_tokens = {
        token.strip().lower()
        for token in upstream_response.getheader("Connection", "").split(",")
        if token.strip()
    }
    blocked = HOP_BY_HOP | connection_tokens | {"content-length"}
    output = []
    for name, value in upstream_response.getheaders():
        lower = name.lower()
        if lower in blocked:
            continue
        if lower == "location" and value.startswith("http://127.0.0.1:8080/"):
            value = value.replace("http://127.0.0.1:8080", "", 1)
        output.append((name, value))
    output.append(("X-Proxy-Backend", "guacamole"))
    return output


def _proxy(path=""):
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return Response(
            "WebSocket proxying is not supported by the Flask server. "
            "Guacamole must use its HTTP tunnel, or be placed behind a WebSocket-capable reverse proxy.",
            status=426,
            headers={"Upgrade": "websocket"},
            mimetype="text/plain",
        )

    try:
        parsed = _upstream()
        conn = _connection(parsed)
        body = request.get_data(cache=False) if request.method not in {"GET", "HEAD"} else None
        conn.request(request.method, _target_path(path), body=body, headers=_forward_headers(parsed))
        upstream = conn.getresponse()
    except (OSError, http.client.HTTPException, RuntimeError) as exc:
        current_app.logger.exception("Guacamole proxy connection failed")
        return Response(
            "Browser RDP gateway is unavailable. Verify the Guacamole containers are running "
            f"and reachable at {os.environ.get('GUACAMOLE_UPSTREAM', DEFAULT_UPSTREAM)}. Error: {exc}",
            status=502,
            mimetype="text/plain",
        )

    headers = _response_headers(upstream)

    @stream_with_context
    def generate():
        try:
            while True:
                chunk = upstream.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                upstream.close()
            finally:
                conn.close()

    return Response(generate(), status=upstream.status, headers=headers,
                    content_type=upstream.getheader("Content-Type"))


def register(app):
    if bp.name in app.blueprints:
        return

    bp.add_url_rule("/guacamole", defaults={"path": ""}, view_func=_proxy,
                    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    bp.add_url_rule("/guacamole/", defaults={"path": ""}, view_func=_proxy,
                    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    bp.add_url_rule("/guacamole/<path:path>", view_func=_proxy,
                    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    app.register_blueprint(bp)
