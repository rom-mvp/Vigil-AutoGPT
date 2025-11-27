from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

from backend.data.block import (
    Block,
    BlockCategory,
    BlockOutput,
    BlockSchemaInput,
    BlockSchemaOutput,
)
from backend.data.model import SchemaField
from backend.util.exceptions import BlockExecutionError
from backend.util.request import Requests
MOCK_ANALYTICS_PAYLOAD: dict[str, Any] = {
    "timeframe": {
        "start": "2025-01-01T00:00:00Z",
        "end": "2025-01-01T12:00:00Z",
    },
    "analytics": {
        "blocked": 12,
        "allowed": 3,
        "rule_breakdown": [
            {"rule_id": "block_botnets", "count": 7},
            {"rule_id": "sql_injection", "count": 5},
        ],
    },
    "incidents": [
        {
            "id": "incident-1",
            "rule_id": "block_botnets",
            "severity": "high",
            "action": "blocked",
        },
        {
            "id": "incident-2",
            "rule_id": "sql_injection",
            "severity": "medium",
            "action": "blocked",
        },
        {
            "id": "incident-3",
            "rule_id": "sql_injection",
            "severity": "low",
            "action": "allowed",
        },
    ],
}


class VigilFirewallBlock(Block):
    """Surfaced firewall incidents and analytics from Vigil."""

    BASE_ENDPOINT = "firewall/analytics"

    class Input(BlockSchemaInput):
        api_base_url: str = SchemaField(
            description="Base Vigil API URL including scheme.",
            default="https://api.vigil.ai/v1",
            advanced=True,
        )
        api_key: str = SchemaField(
            description="Vigil API key with firewall.read scope.",
            placeholder="vigil_sk_live_xxx",
            secret=True,
        )
        workspace_id: str = SchemaField(
            description="Workspace or tenant identifier used inside Vigil.",
            placeholder="workspace_123",
        )
        environment: str = SchemaField(
            description="Environment tag (production, staging, etc.) to filter events.",
            default="production",
        )
        incident_limit: int = SchemaField(
            description="Maximum number of incidents to include in the result.",
            default=50,
            ge=1,
            le=500,
            advanced=True,
        )
        include_rule_analytics: bool = SchemaField(
            description="Include rule-level analytics when available.",
            default=True,
        )
        cached_payload: dict[str, Any] = SchemaField(
            description="Optional Vigil response payload to bypass the live API call.",
            default_factory=dict,
            advanced=True,
        )

    class Output(BlockSchemaOutput):
        completion: dict[str, Any] = SchemaField(
            description="High-level summary that combines the most useful analytics."
        )
        analytics: dict[str, Any] = SchemaField(
            description="Raw analytics payload returned by Vigil."
        )
        incidents: list[dict[str, Any]] = SchemaField(
            description="List of firewall incidents returned by Vigil."
        )

    def __init__(self):
        super().__init__(
            id="0f6b8a27-16da-425d-a0db-9f9d19d1ba4a",
            description=(
                "Fetch the latest firewall incidents from Vigil and emit an analytics "
                "summary that can be consumed by downstream blocks."
            ),
            categories={BlockCategory.SAFETY, BlockCategory.DATA},
            input_schema=VigilFirewallBlock.Input,
            output_schema=VigilFirewallBlock.Output,
            test_input=[
                {
                    "api_key": "mock",
                    "workspace_id": "workspace_demo",
                    "environment": "production",
                    "cached_payload": MOCK_ANALYTICS_PAYLOAD,
                }
            ],
            test_output=[
                (
                    "completion",
                    {
                        "environment": "production",
                        "blocked_requests": 12,
                        "allowed_requests": 3,
                        "unique_rules_triggered": 2,
                        "top_severity": "high",
                        "timeframe_start": "2025-01-01T00:00:00Z",
                        "timeframe_end": "2025-01-01T12:00:00Z",
                        "top_rule": "block_botnets",
                    },
                ),
                ("analytics", dict),
                ("incidents", list),
            ],
        )

    async def run(self, input_data: Input, **kwargs) -> BlockOutput:
        payload = (
            dict(input_data.cached_payload)
            if input_data.cached_payload
            else await self.fetch_vigil_payload(input_data)
        )

        completion, analytics, incidents = self._build_outputs(
            payload,
            environment=input_data.environment,
            limit=input_data.incident_limit,
        )

        yield "completion", completion
        yield "analytics", analytics
        yield "incidents", incidents

    async def fetch_vigil_payload(self, input_data: Input) -> dict[str, Any]:
        base_url = input_data.api_base_url.rstrip("/")
        workspace_segment = quote(input_data.workspace_id.strip("/"))
        endpoint = f"{base_url}/workspaces/{workspace_segment}/{self.BASE_ENDPOINT}"
        params = {
            "environment": input_data.environment,
            "limit": input_data.incident_limit,
        }
        if input_data.include_rule_analytics:
            params["include_rules"] = "true"

        parsed = urlparse(base_url)
        trusted_hosts = [parsed.hostname] if parsed.hostname else []

        headers = {
            "Authorization": f"Bearer {input_data.api_key}",
            "Accept": "application/json",
        }

        try:
            response = await Requests(
                trusted_origins=trusted_hosts or ["api.vigil.ai"],
                raise_for_status=True,
            ).get(endpoint, headers=headers, params=params)
        except Exception as exc:  # pragma: no cover - network errors covered in summary
            raise BlockExecutionError(
                message=f"Failed to contact Vigil Firewall API: {exc}",
                block_name=self.name,
                block_id=self.id,
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise BlockExecutionError(
                message="Vigil Firewall API did not return valid JSON.",
                block_name=self.name,
                block_id=self.id,
            ) from exc

        if not isinstance(payload, dict):
            raise BlockExecutionError(
                message="Unexpected Vigil Firewall response format.",
                block_name=self.name,
                block_id=self.id,
            )

        return payload

    def _build_outputs(
        self, payload: dict[str, Any], *, environment: str, limit: int
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        analytics_raw = payload.get("analytics")
        analytics: dict[str, Any] = (
            analytics_raw if isinstance(analytics_raw, dict) else {}
        )

        incidents_raw = payload.get("incidents")
        incidents: list[dict[str, Any]] = (
            [incident for incident in incidents_raw if isinstance(incident, dict)][
                : max(limit, 1)
            ]
            if isinstance(incidents_raw, list)
            else []
        )

        severity_counts = Counter(
            incident.get("severity", "unknown") for incident in incidents
        )
        rule_ids = {
            incident.get("rule_id") for incident in incidents if incident.get("rule_id")
        }

        completion = {
            "environment": environment,
            "blocked_requests": analytics.get(
                "blocked", self._count_by_action(incidents, "blocked")
            ),
            "allowed_requests": analytics.get(
                "allowed", self._count_by_action(incidents, "allowed")
            ),
            "unique_rules_triggered": len(rule_ids),
            "top_severity": self._top_severity(severity_counts),
            "timeframe_start": self._coerce_timestamp(
                payload.get("timeframe", {}).get("start")
            ),
            "timeframe_end": self._coerce_timestamp(
                payload.get("timeframe", {}).get("end")
            ),
        }

        top_rule = self._top_rule(analytics.get("rule_breakdown"))
        if top_rule:
            completion["top_rule"] = top_rule

        return completion, analytics, incidents

    @staticmethod
    def _count_by_action(incidents: list[dict[str, Any]], action: str) -> int:
        return sum(1 for incident in incidents if incident.get("action") == action)

    @staticmethod
    def _coerce_timestamp(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        return None

    @staticmethod
    def _top_rule(rule_breakdown: Any) -> str | None:
        if not isinstance(rule_breakdown, list):
            return None

        top_entry = None
        for entry in rule_breakdown:
            if not isinstance(entry, dict):
                continue
            if top_entry is None or (
                isinstance(entry.get("count"), (int, float))
                and entry.get("count", 0) > top_entry.get("count", 0)
            ):
                top_entry = entry

        if top_entry and isinstance(top_entry.get("rule_id"), str):
            return top_entry["rule_id"]
        return None

    @staticmethod
    def _top_severity(counts: Counter[str]) -> str | None:
        if not counts:
            return None
        return counts.most_common(1)[0][0]
