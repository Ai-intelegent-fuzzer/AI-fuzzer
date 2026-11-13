from typing import Protocol

from app.integrations.models import (
    ConnectorOperation,
    SyntheticIntegration,
)


class IntegrationAdapter(Protocol):
    def execute(
        self,
        integration: SyntheticIntegration,
        operation: ConnectorOperation,
        *,
        value: str | None,
        current_state: str | None,
    ) -> dict[str, str]: ...


class LocalSyntheticConnectorAdapter:
    """Runs connector operations only against persisted synthetic fixture state."""

    def execute(
        self,
        integration: SyntheticIntegration,
        operation: ConnectorOperation,
        *,
        value: str | None,
        current_state: str | None,
    ) -> dict[str, str]:
        if operation == ConnectorOperation.READ:
            return {
                "record": current_state or integration.synthetic_record,
                "mode": "local_synthetic",
            }
        return {
            "record": value or "[SYNTHETIC] simulated update",
            "mode": "local_synthetic",
        }
