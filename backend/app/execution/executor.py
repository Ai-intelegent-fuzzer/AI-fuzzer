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
