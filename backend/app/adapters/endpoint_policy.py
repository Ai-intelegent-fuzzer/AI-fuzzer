import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpcore
import httpx


class UnsafeTargetEndpointError(ValueError):
    pass


class ResponseTooLargeError(ValueError):
    pass


class _PinnedNetworkBackend(httpcore.SyncBackend):
    def __init__(self, *, allow_private: bool, allow_local_ollama: bool) -> None:
        self.allow_private = allow_private
        self.allow_local_ollama = allow_local_ollama

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        try:
            literal = ipaddress.ip_address(host)
            addresses = [literal]
        except ValueError:
            try:
                addresses = list({
                    ipaddress.ip_address(record[4][0])
                    for record in socket.getaddrinfo(
                        host,
                        port,
                        type=socket.SOCK_STREAM,
                    )
                })
            except (OSError, ValueError):
                raise httpcore.ConnectError("Target hostname could not be safely resolved.") from None

        if not addresses:
            raise httpcore.ConnectError("Target hostname has no usable address.")
        local_ollama = (
            self.allow_local_ollama
            and _local_ollama_enabled()
            and all(address.is_loopback for address in addresses)
        )
        if not self.allow_private and not local_ollama and any(
            not address.is_global for address in addresses
        ):
            raise httpcore.ConnectError("Target resolved to a private or reserved address.")
        selected_address = str(addresses[0])
        return super().connect_tcp(
            selected_address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedHTTPTransport(httpx.HTTPTransport):
    def __init__(self, *, allow_local_ollama: bool = False) -> None:
        super().__init__(trust_env=False)
        self._pool._network_backend = _PinnedNetworkBackend(
            allow_private=_private_targets_enabled(),
            allow_local_ollama=allow_local_ollama,
        )


def bounded_post(
    url: str,
    *,
    headers: dict[str, str],
    json: dict[str, object],
    timeout: float,
    response_size_limit: int,
    allow_local_ollama: bool = False,
) -> httpx.Response:
    limit = max(response_size_limit, 1)
    request_headers = {**headers, "Accept-Encoding": "identity"}
    transport = PinnedHTTPTransport(allow_local_ollama=allow_local_ollama)
    with httpx.Client(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        with client.stream("POST", url, headers=request_headers, json=json) as streamed:
            body = bytearray()
            for chunk in streamed.iter_bytes():
                remaining = limit + 1 - len(body)
                if remaining <= 0:
                    break
                body.extend(chunk[:remaining])
                if len(body) > limit:
                    raise ResponseTooLargeError(
                        "Provider response exceeded the configured safety limit."
                    )
            response_headers = {
                name: value
                for name, value in streamed.headers.items()
                if name.lower() not in {"content-length", "content-encoding"}
            }
            return httpx.Response(
                status_code=streamed.status_code,
                headers=response_headers,
                content=bytes(body),
                request=streamed.request,
            )


_PROVIDER_HOSTS = {
    "groq": "api.groq.com",
    "openai": "api.openai.com",
    "gemini": "generativelanguage.googleapis.com",
    "anthropic": "api.anthropic.com",
    "mistral": "api.mistral.ai",
}


def _private_targets_enabled() -> bool:
    return os.getenv("AI_FUZZER_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _local_ollama_enabled() -> bool:
    return os.getenv("AI_FUZZER_ALLOW_LOCAL_OLLAMA", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _allowed_provider_hosts() -> set[str]:
    configured = os.getenv("AI_FUZZER_ALLOWED_PROVIDER_HOSTS", "")
    return {
        host.strip().rstrip(".").lower()
        for host in configured.split(",")
        if host.strip()
    }


def validate_target_endpoint(
    endpoint: str,
    *,
    provider: str | None = None,
    resolve_dns: bool = True,
    allow_local_ollama: bool = False,
) -> None:
    try:
        parsed = urlsplit(str(endpoint))
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetEndpointError("Target endpoint URL is invalid.") from exc

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise UnsafeTargetEndpointError(
            "Target endpoint must use HTTP or HTTPS and include a hostname."
        )
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetEndpointError(
            "Target endpoint must not contain embedded credentials."
        )
    if parsed.query or parsed.fragment:
        raise UnsafeTargetEndpointError(
            "Target endpoint must not contain a query string or fragment."
        )

    normalized_host = hostname.rstrip(".").lower()
    allow_private = _private_targets_enabled()
    if provider == "ollama" and allow_local_ollama and _local_ollama_enabled():
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        try:
            parsed_ip = ipaddress.ip_address(normalized_host)
        except ValueError:
            parsed_ip = None
        if normalized_host in local_hosts or (parsed_ip is not None and parsed_ip.is_loopback):
            return

    if provider and not allow_private:
        expected_host = _PROVIDER_HOSTS.get(provider)
        allowed_hosts = _allowed_provider_hosts()
        if normalized_host != expected_host and normalized_host not in allowed_hosts:
            raise UnsafeTargetEndpointError(
                "Provider endpoint host is not approved. Use the provider's official "
                "API host or configure AI_FUZZER_ALLOWED_PROVIDER_HOSTS."
            )

    if allow_private:
        return
    if parsed.scheme != "https":
        raise UnsafeTargetEndpointError(
            "Non-local target endpoints must use HTTPS."
        )
    if (
        normalized_host == "localhost"
        or normalized_host.endswith(".localhost")
        or normalized_host.endswith(".local")
        or normalized_host.endswith(".internal")
    ):
        raise UnsafeTargetEndpointError(
            "Local and internal target hostnames require "
            "AI_FUZZER_ALLOW_PRIVATE_TARGETS=true."
        )

    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        address = None

    if address is not None:
        if not address.is_global:
            raise UnsafeTargetEndpointError(
                "Private or reserved target IP addresses are not allowed."
            )
        return

    if not resolve_dns:
        return

    try:
        addresses = {
            ipaddress.ip_address(record[4][0])
            for record in socket.getaddrinfo(
                normalized_host,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError):
        raise UnsafeTargetEndpointError(
            "Target hostname could not be safely resolved."
        ) from None

    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeTargetEndpointError(
            "Target hostname resolves to a private or reserved address."
        )
