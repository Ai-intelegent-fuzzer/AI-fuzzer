import os
import time
from collections.abc import Sequence
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.adapters.models import AIProvider, Target, TargetType
from app.fuzzing.models import FuzzCase
from .models import ExecutionResult

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class FuzzExecutor:
    MAX_TIMEOUT_SECONDS = 120.0
    MAX_RETRIES = 5
    MAX_RESPONSE_SIZE = 10000

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
                with httpx.Client(timeout=timeout) as client:
                    with client.stream(
                        "POST",
                        str(target.endpoint),
                        json={"prompt": prompt},
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
            except httpx.TimeoutException as exc:
                failure_reason = str(exc) or "Target request timed out."
                final_status = "timeout"
            except httpx.NetworkError as exc:
                failure_reason = str(exc) or "Target network request failed."
                final_status = "error"
            except httpx.HTTPError as exc:
                failure_reason = str(exc)
                final_status = "error"
                break
            except Exception as exc:
                failure_reason = str(exc)
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
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
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
            "generationConfig": {"maxOutputTokens": 256},
        }
        system_instruction = fuzz_case.metadata.get(
            "security_test_system_instruction"
        )
        if isinstance(system_instruction, str) and system_instruction.strip():
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction.strip()[:4000]}]
            }

        for attempt in range(retries + 1):
            try:
                response = httpx.post(
                    endpoint,
                    headers={
                        "x-goog-api-key": api_key,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=timeout,
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
        env_prefix = "GROQ" if target.provider == AIProvider.GROQ else "OPENAI"
        api_key = os.getenv(f"{env_prefix}_API_KEY", "").strip()
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
        if not api_key:
            return result(
                status="configuration_error",
                message=f"Missing {env_prefix}_API_KEY in backend/.env or environment.",
                failure_reason="provider_api_key_missing",
            )

        messages = []
        system_instruction = fuzz_case.metadata.get(
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
        payload = {"model": model, "messages": messages, "max_tokens": 256}
        retries = min(max(max_retries, 0), self.MAX_RETRIES)
        last_status_code: int | None = None

        for attempt in range(retries + 1):
            try:
                response = httpx.post(
                    str(target.endpoint),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=timeout,
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
                    choices = data["choices"]
                    content = choices[0]["message"]["content"]
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
                usage = data.get("usage") or {}
                body = content[:limit]
                return result(
                    status="completed",
                    status_code=response.status_code,
                    message="Real provider inference completed.",
                    response_body=body,
                    attempts=attempt + 1,
                    prompt_tokens=usage.get("prompt_tokens"),
                    completion_tokens=usage.get("completion_tokens"),
                    total_tokens=usage.get("total_tokens"),
                    response_truncated=len(content) > limit,
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


fuzz_executor = FuzzExecutor()
