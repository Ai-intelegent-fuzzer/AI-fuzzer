from __future__ import annotations

from urllib.parse import urlsplit

import httpx


MAX_PROVIDER_RESPONSE_BYTES = 1_000_000
_PROVIDER_HOSTS = {
    "openai": "api.openai.com",
    "groq": "api.groq.com",
    "gemini": "generativelanguage.googleapis.com",
}
_PROVIDER_PATHS = {
    "openai": "/v1/chat/completions",
    "groq": "/openai/v1/chat/completions",
}


def validate_provider_endpoint(provider: str, endpoint: str) -> None:
    """Reject non-HTTPS or untrusted endpoints before attaching provider credentials."""
    provider = str(provider).lower()
    expected_host = _PROVIDER_HOSTS.get(provider)
    parsed = urlsplit(endpoint)
    if (
        expected_host is None
        or parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ValueError("Provider endpoint is not trusted; use the official HTTPS endpoint.")

    expected_path = _PROVIDER_PATHS.get(provider)
    if expected_path and parsed.path.rstrip("/") != expected_path:
        raise ValueError("Provider endpoint path is not the supported API route.")
    if provider == "gemini" and not parsed.path.startswith("/v1beta"):
        raise ValueError("Gemini endpoint must use the supported /v1beta API path.")


def bounded_post(
    url: str,
    *,
    headers: dict[str, str],
    json: dict[str, object],
    timeout: float,
    max_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
) -> httpx.Response:
    """POST without redirects and read at most max_bytes + 1 from a successful body."""
    cap = max(1, min(int(max_bytes), MAX_PROVIDER_RESPONSE_BYTES))
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        with client.stream(
            "POST",
            url,
            headers={**headers, "Accept-Encoding": "identity"},
            json=json,
        ) as streamed:
            # Never consume provider error bodies; they may contain diagnostics or secrets.
            if streamed.status_code < 200 or streamed.status_code >= 300:
                return httpx.Response(
                    status_code=streamed.status_code,
                    headers=streamed.headers,
                    content=b"",
                    request=streamed.request,
                )

            body = bytearray()
            oversized = False
            for chunk in streamed.iter_bytes(chunk_size=16_384):
                remaining = cap + 1 - len(body)
                if remaining <= 0:
                    oversized = True
                    break
                body.extend(chunk[:remaining])
                if len(body) > cap:
                    oversized = True
                    break

            if oversized:
                body.clear()
            return httpx.Response(
                status_code=streamed.status_code,
                headers=streamed.headers,
                content=bytes(body),
                request=streamed.request,
                extensions={"ai_fuzzer_response_too_large": oversized},
            )
