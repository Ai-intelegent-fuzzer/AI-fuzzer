import time

import httpx

from app.adapters.models import Target
from .models import ConnectivityResult, ConnectivityStatus


class ConnectivityTester:

    def test(self, target: Target) -> ConnectivityResult:
        start = time.perf_counter()

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(str(target.endpoint))

            elapsed = (time.perf_counter() - start) * 1000

            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.REACHABLE,
                status_code=response.status_code,
                response_time_ms=round(elapsed, 2),
                message="Target endpoint is reachable.",
            )

        except httpx.TimeoutException:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.TIMEOUT,
                message="Target request timed out.",
            )

        except httpx.HTTPError as exc:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.ERROR,
                message=f"HTTP error: {exc}",
            )

        except Exception as exc:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.ERROR,
                message=f"Unexpected error: {exc}",
            )


connectivity_tester = ConnectivityTester()
