import logging
import os
import time
from collections.abc import Sequence
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.adapters.endpoint_policy import (
    ResponseTooLargeError,
    PinnedHTTPTransport,
    UnsafeTargetEndpointError,
    bounded_post,
    validate_target_endpoint,
)
from app.adapters.models import AIProvider, Target, TargetType
from app.fuzzing.models import FuzzCase
from .models import ExecutionResult

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class FuzzExecutor:
    MAX_TIMEOUT_SECONDS = 120.0
    MAX_RETRIES = 5
    MAX_RESPONSE_SIZE = 10000
    MAX_PROVIDER_BODY_SIZE = 1_000_000

    def execute(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float = 30.0,
        max_retries: int = 0,
        response_size_limit: int = MAX_RESPONSE_SIZE,
        conversation_context: Sequence[str] | None = None,
    ) -> ExecutionResult:
        provider = (
            target.provider.value
            if target.target_type == TargetType.OPENAI_COMPATIBLE
            else None
        )
        allow_local_ollama = target.provider == AIProvider.OLLAMA
        try:
            validate_target_endpoint(
                str(target.endpoint),
                provider=provider if provider != "custom" else None,
                allow_local_ollama=allow_local_ollama,
            )
        except UnsafeTargetEndpointError:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status="configuration_error",
                message="Target endpoint is not allowed by the server's endpoint policy.",
                failure_reason="target_endpoint_blocked",
                provider=provider,
                model=target.model,
            )

        if target.target_type == TargetType.OPENAI_COMPATIBLE:
            if target.provider == AIProvider.GEMINI:
                return self._execute_gemini(
                    target,
                    fuzz_case,
                    timeout_seconds=timeout_seconds,
                    max_retries=max_retries,
                    response_size_limit=response_size_limit,
                    conversation_context=conversation_context,
                )
            if target.provider == AIProvider.ANTHROPIC:
                return self._execute_anthropic(
                    target,
                    fuzz_case,
                    timeout_seconds=timeout_seconds,
                    max_retries=max_retries,
                    response_size_limit=response_size_limit,
                    conversation_context=conversation_context,
                )
            if target.provider == AIProvider.OLLAMA:
                return self._execute_ollama(
                    target,
                    fuzz_case,
                    timeout_seconds=timeout_seconds,
                    max_retries=max_retries,
                    response_size_limit=response_size_limit,
                    conversation_context=conversation_context,
                )
            return self._execute_chat_completion(
                target,
                fuzz_case,
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                response_size_limit=response_size_limit,
                conversation_context=conversation_context,
            )

        start = time.perf_counter()
        timeout = min(max(timeout_seconds, 0.1), self.MAX_TIMEOUT_SECONDS)
        retry_limit = min(max(max_retries, 0), self.MAX_RETRIES)
        response_limit = min(max(response_size_limit, 0), self.MAX_RESPONSE_SIZE)
        prompt = fuzz_case.prompt
        if conversation_context:
            history = "\n".join(
                f"Turn {index}: {turn}"
                for index, turn in enumerate(conversation_context, start=1)
            )
            prompt = f"Conversation history:\n{history}\n\nCurrent turn:\n{prompt}"

        attempts = 0
        response: httpx.Response | None = None
        failure_reason: str | None = None
        final_status = "error"
        response_truncated = False

        while attempts <= retry_limit:
            attempts += 1
            try:
                transport = PinnedHTTPTransport(
                    allow_local_ollama=allow_local_ollama
                )
                with httpx.Client(
                    timeout=timeout,
                    transport=transport,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    with client.stream(
                        "POST",
                        str(target.endpoint),
                        json={"prompt": prompt},
                        follow_redirects=False,
                    ) as streamed:
                        if streamed.status_code >= 500 and attempts <= retry_limit:
                            continue
                        response_content = bytearray()
                        for chunk in streamed.iter_bytes():
                            remaining = response_limit + 1 - len(response_content)
                            if remaining <= 0:
                                break
                            response_content.extend(chunk[:remaining])
                            if len(response_content) > response_limit:
                                break
                        response_truncated = len(response_content) > response_limit
                        response = httpx.Response(
                            status_code=streamed.status_code,
                            headers=streamed.headers,
                            content=bytes(response_content[:response_limit]),
                            request=streamed.request,
                        )
                if 200 <= response.status_code < 300:
                    final_status = "completed"
                elif 400 <= response.status_code < 500:
                    final_status = "target_rejected"
                elif response.status_code >= 500:
                    final_status = "target_error"
                else:
                    final_status = "completed"
                break
            except httpx.TimeoutException:
                failure_reason = "Target request timed out."
                final_status = "timeout"
            except httpx.NetworkError:
                failure_reason = "Target network request failed."
                final_status = "error"
            except httpx.HTTPError:
                failure_reason = "Target HTTP transport failed."
                final_status = "error"
                break
            except Exception as exc:
                logging.getLogger(__name__).error(
                    "Target execution failed for target_id=%s case_id=%s; "
                    "exception_type=%s",
                    target.target_id,
                    fuzz_case.case_id,
                    type(exc).__name__,
                )
                failure_reason = "Target request failed due to an internal execution error."
                final_status = "error"
                break

        elapsed = (time.perf_counter() - start) * 1000
        body = response.text if response is not None else None

        if response is not None:
            message = (
                "Fuzz case executed successfully."
                if final_status == "completed"
                else f"Target returned HTTP {response.status_code}."
            )
            if final_status == "target_rejected":
                message = f"Target rejected the fuzz request with HTTP {response.status_code}."
            elif final_status == "target_error":
                message = f"Target returned server error HTTP {response.status_code}."
            failure_reason = (
                message
                if final_status in {"target_rejected", "target_error"}
                else None
            )
        else:
            message = failure_reason or "Target request failed."

        return ExecutionResult(
            target_id=target.target_id,
            case_id=fuzz_case.case_id,
            status=final_status,
            status_code=response.status_code if response is not None else None,
            response_time_ms=round(elapsed, 2),
            response_body=body,
            message=message,
            attempts=attempts,
            retries=max(attempts - 1, 0),
            failure_reason=failure_reason,
            response_truncated=response_truncated,
        )


    def _execute_gemini(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float,
        max_retries: int,
        response_size_limit: int,
        conversation_context: Sequence[str] | None,
    ) -> ExecutionResult:
        start = time.perf_counter()
        api_key = self._api_key(target, "GEMINI_API_KEY")
        model = target.model or os.getenv("GEMINI_MODEL", "").strip()
        limit = min(max(response_size_limit, 1), self.MAX_RESPONSE_SIZE)
        timeout = min(max(timeout_seconds, 0.1), self.MAX_TIMEOUT_SECONDS)
        retries = min(max(max_retries, 0), self.MAX_RETRIES)

        def result(
            *,
            status: str,
            message: str,
            status_code: int | None = None,
            response_body: str | None = None,
            failure_reason: str | None = None,
            attempts: int = 1,
            prompt_tokens: int | None = None,
            completion_tokens: int | None = None,
            total_tokens: int | None = None,
            response_truncated: bool = False,
        ) -> ExecutionResult:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status=status,
                status_code=status_code,
                response_time_ms=round((time.perf_counter() - start) * 1000, 2),
                response_body=response_body,
                message=message,
                attempts=attempts,
                retries=max(attempts - 1, 0),
                failure_reason=failure_reason,
                provider="gemini",
                model=model or None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                response_truncated=response_truncated,
            )

        if not model:
            return result(
                status="configuration_error",
                message="Set target.model or GEMINI_MODEL.",
                failure_reason="provider_model_missing",
            )
        if not api_key:
            return result(
                status="configuration_error",
                message="Missing GEMINI_API_KEY in backend/.env or environment.",
                failure_reason="provider_api_key_missing",
            )

        endpoint = str(target.endpoint).rstrip("/")
        if "/models/" in endpoint:
            endpoint = endpoint.split("/models/", 1)[0].rstrip("/")
        elif endpoint.endswith("/models"):
            endpoint = endpoint[:-len("/models")].rstrip("/")
        endpoint = f"{endpoint}/models/{model}:generateContent"

        prompt = fuzz_case.prompt
        if conversation_context:
            history = "\n".join(
                f"Turn {index}: {turn}"
                for index, turn in enumerate(conversation_context, start=1)
            )
            prompt = f"Conversation history:\n{history}\n\nCurrent turn:\n{prompt}"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "maxOutputTokens": target.max_output_tokens,
                "temperature": target.temperature,
            },
        }
        system_instruction = target.system_prompt or fuzz_case.metadata.get(
            "security_test_system_instruction"
        )
        if isinstance(system_instruction, str) and system_instruction.strip():
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction.strip()[:4000]}]
            }

        for attempt in range(retries + 1):
            try:
                response = bounded_post(
                    endpoint,
                    headers={
                        "x-goog-api-key": api_key,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=timeout,
                    response_size_limit=self.MAX_PROVIDER_BODY_SIZE,
                )

                if response.status_code >= 500 and attempt < retries:
                    continue

                if response.status_code == 429:
                    return result(
                        status="rate_limited",
                        status_code=429,
                        message="Gemini rate limit or quota reached.",
                        failure_reason="provider_rate_limited",
                        attempts=attempt + 1,
                    )

                if response.status_code in (401, 403):
                    return result(
                        status="authentication_error",
                        status_code=response.status_code,
                        message="Gemini rejected the API credentials or access.",
                        failure_reason="provider_authentication_failed",
                        attempts=attempt + 1,
                    )

                if response.status_code >= 400:
                    return result(
                        status="target_error",
                        status_code=response.status_code,
                        message=(
                            f"Gemini returned HTTP {response.status_code}. "
                            "Check the endpoint, model, and API access."
                        ),
                        failure_reason="provider_request_rejected",
                        attempts=attempt + 1,
                    )

                try:
                    data = response.json()

                    # Gemini can block a prompt before returning any candidates.
                    prompt_feedback = data.get("promptFeedback", {})
                    block_reason = (
                        prompt_feedback.get("blockReason")
                        if isinstance(prompt_feedback, dict)
                        else None
                    )
                    if (
                        isinstance(block_reason, str)
                        and block_reason.strip()
                        and block_reason.upper() != "BLOCK_REASON_UNSPECIFIED"
                    ):
                        return result(
                            status="blocked",
                            status_code=response.status_code,
                            message="Gemini blocked the prompt under its safety controls.",
                            failure_reason="provider_safety_blocked",
                            attempts=attempt + 1,
                        )

                    candidate = data["candidates"][0]
                    finish_reason = candidate.get("finishReason")
                    safety_finish_reasons = {
                        "SAFETY",
                        "RECITATION",
                        "BLOCKLIST",
                        "PROHIBITED_CONTENT",
                        "SPII",
                        "IMAGE_SAFETY",
                    }
                    if (
                        isinstance(finish_reason, str)
                        and finish_reason.upper() in safety_finish_reasons
                    ):
                        return result(
                            status="blocked",
                            status_code=response.status_code,
                            message="Gemini blocked the response under its safety controls.",
                            failure_reason="provider_safety_blocked",
                            attempts=attempt + 1,
                        )

                    parts = candidate["content"]["parts"]
                    content = "".join(
                        part["text"] for part in parts
                        if isinstance(part.get("text"), str)
                    )
                    if not isinstance(content, str):
                        raise ValueError("Unexpected response text")
                except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                    return result(
                        status="invalid_response",
                        status_code=response.status_code,
                        message="Gemini returned an unexpected generateContent response format.",
                        failure_reason="provider_response_malformed",
                        attempts=attempt + 1,
                    )

                if not content.strip():
                    return result(
                        status="invalid_response",
                        status_code=response.status_code,
                        message="Gemini returned no usable candidate text.",
                        failure_reason="provider_response_empty",
                        attempts=attempt + 1,
                    )

                usage = data.get("usageMetadata") or {}
                return result(
                    status="completed",
                    status_code=response.status_code,
                    message="Real Gemini inference completed.",
                    response_body=content[:limit],
                    attempts=attempt + 1,
                    prompt_tokens=usage.get("promptTokenCount"),
                    completion_tokens=usage.get("candidatesTokenCount"),
                    total_tokens=usage.get("totalTokenCount"),
                    response_truncated=len(content) > limit,
                )

            except ResponseTooLargeError:
                return result(
                    status="invalid_response",
                    message="Gemini response exceeded the configured safety limit.",
                    failure_reason="provider_response_too_large",
                    attempts=attempt + 1,
                )
            except httpx.TimeoutException:
                if attempt < retries:
                    continue
                return result(
                    status="timeout",
                    message="Gemini request timed out.",
                    failure_reason="provider_timeout",
                    attempts=attempt + 1,
                )
            except httpx.HTTPError:
                if attempt < retries:
                    continue
                return result(
                    status="network_error",
                    message="Could not connect to the Gemini API endpoint.",
                    failure_reason="provider_network_error",
                    attempts=attempt + 1,
                )

        return result(
            status="target_error",
            message="Gemini request failed after the configured attempts.",
            failure_reason="provider_unavailable",
            attempts=retries + 1,
        )

    def _execute_chat_completion(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float,
        max_retries: int,
        response_size_limit: int,
        conversation_context: Sequence[str] | None,
    ) -> ExecutionResult:
        start = time.perf_counter()
        provider = target.provider.value
        env_prefix = {
            AIProvider.GROQ: "GROQ",
            AIProvider.MISTRAL: "MISTRAL",
            AIProvider.CUSTOM: "CUSTOM",
        }.get(target.provider, "OPENAI")
        api_key = self._api_key(target, f"{env_prefix}_API_KEY")
        model = target.model or os.getenv(f"{env_prefix}_MODEL", "")
        limit = min(max(response_size_limit, 1), self.MAX_RESPONSE_SIZE)
        timeout = min(max(timeout_seconds, 0.1), self.MAX_TIMEOUT_SECONDS)

        def result(
            *,
            status: str,
            message: str,
            status_code: int | None = None,
            response_body: str | None = None,
            failure_reason: str | None = None,
            attempts: int = 1,
            prompt_tokens: int | None = None,
            completion_tokens: int | None = None,
            total_tokens: int | None = None,
            response_truncated: bool = False,
        ) -> ExecutionResult:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status=status,
                status_code=status_code,
                response_time_ms=round((time.perf_counter() - start) * 1000, 2),
                response_body=response_body,
                message=message,
                attempts=attempts,
                retries=max(attempts - 1, 0),
                failure_reason=failure_reason,
                provider=provider,
                model=model or None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                response_truncated=response_truncated,
            )

        if not model:
            return result(
                status="configuration_error",
                message=f"Set target.model or {env_prefix}_MODEL.",
                failure_reason="provider_model_missing",
            )
        if not api_key and target.provider != AIProvider.OLLAMA:
            return result(
                status="configuration_error",
                message=f"Missing {env_prefix}_API_KEY in backend/.env or environment.",
                failure_reason="provider_api_key_missing",
            )

        messages = []
        system_instruction = target.system_prompt or fuzz_case.metadata.get(
            "security_test_system_instruction"
        )
        if isinstance(system_instruction, str) and system_instruction.strip():
            messages.append({
                "role": "system",
                "content": system_instruction.strip()[:4000],
            })
        if conversation_context:
            for turn in conversation_context:
                messages.append({"role": "user", "content": turn})
        messages.append({"role": "user", "content": fuzz_case.prompt})
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": target.max_output_tokens,
            "temperature": target.temperature,
        }
        endpoint = self._request_endpoint(target)
        responses_api = (
            target.provider == AIProvider.OPENAI
            and endpoint.rstrip("/").endswith("/responses")
        )
        if responses_api:
            payload = {
                "model": model,
                "input": [{"role": "user", "content": fuzz_case.prompt}],
                "max_output_tokens": target.max_output_tokens,
                "temperature": target.temperature,
            }
            if isinstance(system_instruction, str) and system_instruction.strip():
                payload["instructions"] = system_instruction.strip()[:4000]
        retries = min(max(max_retries, 0), self.MAX_RETRIES)
        last_status_code: int | None = None

        for attempt in range(retries + 1):
            try:
                headers = {"Content-Type": "application/json"}
                if api_key:
                    if target.provider == AIProvider.CUSTOM and target.auth_header.lower() != "authorization":
                        headers[target.auth_header] = api_key
                    else:
                        headers["Authorization"] = f"Bearer {api_key}"
                response = bounded_post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                    response_size_limit=self.MAX_PROVIDER_BODY_SIZE,
                )
                last_status_code = response.status_code
                if response.status_code >= 500 and attempt < retries:
                    continue
                if response.status_code == 429:
                    return result(
                        status="rate_limited",
                        status_code=429,
                        message="Provider rate limit or quota reached.",
                        failure_reason="provider_rate_limited",
                        attempts=attempt + 1,
                    )
                if response.status_code in (401, 403):
                    return result(
                        status="authentication_error",
                        status_code=response.status_code,
                        message="Provider rejected the API credentials or access.",
                        failure_reason="provider_authentication_failed",
                        attempts=attempt + 1,
                    )
                if response.status_code >= 400:
                    return result(
                        status="target_error",
                        status_code=response.status_code,
                        message=f"Provider returned HTTP {response.status_code}. Check endpoint, model access, and request settings.",
                        failure_reason="provider_request_rejected",
                        attempts=attempt + 1,
                    )
                try:
                    data = response.json()
                    if responses_api:
                        output_text = data.get("output_text")
                        if isinstance(output_text, str):
                            content = output_text
                        else:
                            content = "".join(
                                part.get("text", "")
                                for output in data["output"]
                                for part in output.get("content", [])
                                if part.get("type") in {"output_text", "refusal"}
                            )
                    else:
                        message = data["choices"][0]["message"]
                        raw_content = message.get("content")
                        if isinstance(raw_content, str):
                            content = raw_content
                        elif isinstance(raw_content, list):
                            content = "".join(
                                part["text"]
                                for part in raw_content
                                if isinstance(part, dict)
                                and part.get("type") in {"text", "output_text"}
                                and isinstance(part.get("text"), str)
                            )
                        elif raw_content is None and isinstance(message.get("refusal"), str):
                            content = message["refusal"]
                        else:
                            raise ValueError("Unexpected message content")
                    if not isinstance(content, str):
                        raise ValueError("Unexpected message content")
                except (ValueError, KeyError, IndexError, TypeError):
                    return result(
                        status="invalid_response",
                        status_code=response.status_code,
                        message="Provider returned an unexpected chat-completions response format.",
                        failure_reason="provider_response_malformed",
                        attempts=attempt + 1,
                    )
                if not content.strip():
                    return result(
                        status="invalid_response",
                        status_code=response.status_code,
                        message="Provider returned no usable text.",
                        failure_reason="provider_response_empty",
                        attempts=attempt + 1,
                    )
                usage = data.get("usage") or {}
                body = content[:limit]
                prompt_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
                completion_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
                return result(
                    status="completed",
                    status_code=response.status_code,
                    message="Real provider inference completed.",
                    response_body=body,
                    attempts=attempt + 1,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=usage.get(
                        "total_tokens",
                        prompt_tokens + completion_tokens
                        if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int)
                        else None,
                    ),
                    response_truncated=len(content) > limit,
                )
            except ResponseTooLargeError:
                return result(
                    "invalid_response",
                    "Provider response exceeded the configured safety limit.",
                    failure_reason="provider_response_too_large",
                    attempts=attempt + 1,
                )
            except httpx.TimeoutException:
                if attempt < retries:
                    continue
                return result(
                    status="timeout",
                    message="Provider request timed out.",
                    failure_reason="provider_timeout",
                    attempts=attempt + 1,
                )
            except httpx.HTTPError:
                if attempt < retries:
                    continue
                return result(
                    status="network_error",
                    message="Could not connect to the provider endpoint.",
                    failure_reason="provider_network_error",
                    attempts=attempt + 1,
                )

        return result(
            status="target_error",
            status_code=last_status_code,
            message="Provider request failed after the configured attempts.",
            failure_reason="provider_unavailable",
            attempts=retries + 1,
        )

    @staticmethod
    def _api_key(target: Target, environment_name: str) -> str:
        if target.api_key:
            return target.api_key.get_secret_value()
        return os.getenv(environment_name, "").strip()

    @staticmethod
    def _request_endpoint(target: Target) -> str:
        base = str(target.endpoint).rstrip("/")
        if target.api_path:
            path = target.api_path.strip("/")
            if base.endswith(f"/{path}"):
                return base
            return f"{base}/{path}"
        if target.provider == AIProvider.ANTHROPIC:
            if base.endswith("/v1/messages"):
                return base
            return f"{base}/messages" if base.endswith("/v1") else f"{base}/v1/messages"
        if target.provider == AIProvider.OLLAMA:
            if base.endswith("/api/chat"):
                return base
            return f"{base}/chat" if base.endswith("/api") else f"{base}/api/chat"
        if target.provider in {AIProvider.OPENAI, AIProvider.GROQ, AIProvider.MISTRAL}:
            if base.endswith("/chat/completions") or base.endswith("/responses"):
                return base
            return f"{base}/chat/completions" if base.endswith("/v1") else base
        return base

    def _execute_anthropic(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float,
        max_retries: int,
        response_size_limit: int,
        conversation_context: Sequence[str] | None,
    ) -> ExecutionResult:
        return self._execute_native_provider(
            target,
            fuzz_case,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            response_size_limit=response_size_limit,
            conversation_context=conversation_context,
            provider_kind="anthropic",
        )

    def _execute_ollama(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float,
        max_retries: int,
        response_size_limit: int,
        conversation_context: Sequence[str] | None,
    ) -> ExecutionResult:
        return self._execute_native_provider(
            target,
            fuzz_case,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            response_size_limit=response_size_limit,
            conversation_context=conversation_context,
            provider_kind="ollama",
        )

    def _execute_native_provider(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float,
        max_retries: int,
        response_size_limit: int,
        conversation_context: Sequence[str] | None,
        provider_kind: str,
    ) -> ExecutionResult:
        start = time.perf_counter()
        model = target.model or ""
        key_environment = "ANTHROPIC_API_KEY" if provider_kind == "anthropic" else "OLLAMA_API_KEY"
        api_key = self._api_key(target, key_environment)
        endpoint = self._request_endpoint(target)
        timeout = min(max(timeout_seconds, 0.1), self.MAX_TIMEOUT_SECONDS)
        retries = min(max(max_retries, 0), self.MAX_RETRIES)
        limit = min(max(response_size_limit, 1), self.MAX_RESPONSE_SIZE)

        def result(
            status: str,
            message: str,
            *,
            failure_reason: str | None = None,
            status_code: int | None = None,
            response_body: str | None = None,
            attempts: int = 1,
            prompt_tokens: int | None = None,
            completion_tokens: int | None = None,
            total_tokens: int | None = None,
            response_truncated: bool = False,
        ) -> ExecutionResult:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status=status,
                status_code=status_code,
                response_time_ms=round((time.perf_counter() - start) * 1000, 2),
                response_body=response_body,
                message=message,
                attempts=attempts,
                retries=max(attempts - 1, 0),
                failure_reason=failure_reason,
                provider=target.provider.value,
                model=model or None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                response_truncated=response_truncated,
            )

        if not model:
            return result("configuration_error", "A model name must be configured.", failure_reason="provider_model_missing")
        if provider_kind == "anthropic" and not api_key:
            return result("configuration_error", "Configure an Anthropic API key for this target.", failure_reason="provider_api_key_missing")

        system_prompt = target.system_prompt or fuzz_case.metadata.get("security_test_system_instruction")
        user_content = fuzz_case.prompt
        if conversation_context:
            user_content = "\n".join([*conversation_context, user_content])
        headers = {"Content-Type": "application/json"}
        if provider_kind == "anthropic":
            headers.update({
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            })
            messages = [{"role": "user", "content": user_content}]
            payload: dict[str, object] = {
                "model": model,
                "max_tokens": target.max_output_tokens,
                "temperature": target.temperature,
                "messages": messages,
            }
            if isinstance(system_prompt, str) and system_prompt.strip():
                payload["system"] = system_prompt.strip()[:4000]
        else:
            messages = []
            if isinstance(system_prompt, str) and system_prompt.strip():
                messages.append({"role": "system", "content": system_prompt.strip()[:4000]})
            messages.append({"role": "user", "content": user_content})
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": target.temperature,
                    "num_predict": target.max_output_tokens,
                },
            }

        if api_key and provider_kind == "ollama":
            headers["Authorization"] = f"Bearer {api_key}"
        for attempt in range(retries + 1):
            try:
                response = bounded_post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                    response_size_limit=self.MAX_PROVIDER_BODY_SIZE,
                    allow_local_ollama=provider_kind == "ollama",
                )
                if response.status_code == 429:
                    return result("rate_limited", "Provider rate limit or quota reached.", failure_reason="provider_rate_limited", status_code=429, attempts=attempt + 1)
                if response.status_code in (401, 403):
                    return result("authentication_error", "Provider rejected the credentials or access.", failure_reason="provider_authentication_failed", status_code=response.status_code, attempts=attempt + 1)
                if response.status_code >= 500 and attempt < retries:
                    continue
                if response.status_code >= 400:
                    return result("target_error", f"Provider returned HTTP {response.status_code}. Check endpoint and model access.", failure_reason="provider_request_rejected", status_code=response.status_code, attempts=attempt + 1)
                try:
                    data = response.json()
                    if provider_kind == "anthropic":
                        content = "".join(
                            block["text"] for block in data["content"]
                            if block.get("type") == "text" and isinstance(block.get("text"), str)
                        )
                        usage = data.get("usage") or {}
                        prompt_tokens = usage.get("input_tokens")
                        completion_tokens = usage.get("output_tokens")
                    else:
                        content = data["message"]["content"]
                        prompt_tokens = data.get("prompt_eval_count")
                        completion_tokens = data.get("eval_count")
                    if not isinstance(content, str) or not content:
                        raise ValueError("Empty provider response")
                except (ValueError, KeyError, IndexError, TypeError):
                    return result("invalid_response", "Provider returned an empty or malformed response.", failure_reason="provider_response_malformed", status_code=response.status_code, attempts=attempt + 1)
                total_tokens = (
                    prompt_tokens + completion_tokens
                    if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int)
                    else None
                )
                return result(
                    "completed",
                    "Provider inference completed.",
                    status_code=response.status_code,
                    response_body=content[:limit],
                    attempts=attempt + 1,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    response_truncated=len(content) > limit,
                )
            except ResponseTooLargeError:
                return result(
                    "invalid_response",
                    "Provider response exceeded the configured safety limit.",
                    failure_reason="provider_response_too_large",
                    attempts=attempt + 1,
                )
            except httpx.TimeoutException:
                if attempt < retries:
                    continue
                return result("timeout", "Provider request timed out.", failure_reason="provider_timeout", attempts=attempt + 1)
            except httpx.HTTPError:
                if attempt < retries:
                    continue
                return result("network_error", "Could not connect to the provider endpoint.", failure_reason="provider_network_error", attempts=attempt + 1)

        return result("target_error", "Provider request failed after the configured attempts.", failure_reason="provider_unavailable", attempts=retries + 1)


fuzz_executor = FuzzExecutor()
