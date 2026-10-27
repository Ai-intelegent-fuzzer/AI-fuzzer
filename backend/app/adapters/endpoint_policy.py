import ipaddress
import os
import socket
from urllib.parse import urlsplit


class UnsafeTargetEndpointError(ValueError):
    pass


_PROVIDER_HOSTS = {
    "groq": "api.groq.com",
    "openai": "api.openai.com",
    "gemini": "generativelanguage.googleapis.com",
}


def _private_targets_enabled() -> bool:
    return os.getenv("AI_FUZZER_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {
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
