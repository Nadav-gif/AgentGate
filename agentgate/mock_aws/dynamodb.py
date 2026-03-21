"""Mock DynamoDB service — in-memory table storage."""

from __future__ import annotations

import logging
from typing import Any

from agentgate.mock_aws.base import MockResponse, MockServiceRegistry

logger = logging.getLogger(__name__)


class MockDynamoDB:
    """In-memory DynamoDB mock supporting Query and PutItem."""

    def __init__(self) -> None:
        # Storage: {table_name: [item_dict, ...]}
        self._tables: dict[str, list[dict[str, Any]]] = {}

    def register(self, registry: MockServiceRegistry) -> None:
        """Register all DynamoDB handlers with the service registry."""
        registry.register("dynamodb:Query", self.query)
        registry.register("dynamodb:PutItem", self.put_item)

    def query(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Query items from a mock DynamoDB table.

        Params:
            TableName: the table to query
            KeyConditionExpression: simple "partition_key = value" matching
            ExpressionAttributeValues: {":val": {"S": "value"}}
        """
        table_name = params.get("TableName", "")
        if not table_name:
            return MockResponse(success=False, error="Missing required parameter: TableName")

        if table_name not in self._tables:
            return MockResponse(
                success=False,
                error=f"ResourceNotFoundException: Requested resource not found: Table: {table_name}",
            )

        # Simple key matching: extract the key and value from ExpressionAttributeValues
        items = self._tables[table_name]
        filtered = self._apply_filter(items, params)

        return MockResponse(
            success=True,
            response={
                "Items": filtered,
                "Count": len(filtered),
                "ScannedCount": len(items),
            },
        )

    def put_item(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Put an item into a mock DynamoDB table.

        Params:
            TableName: the table to write to
            Item: the item dict (in DynamoDB format with type descriptors)
        """
        table_name = params.get("TableName", "")
        if not table_name:
            return MockResponse(success=False, error="Missing required parameter: TableName")

        if table_name not in self._tables:
            return MockResponse(
                success=False,
                error=f"ResourceNotFoundException: Requested resource not found: Table: {table_name}",
            )

        item = params.get("Item")
        if not item or not isinstance(item, dict):
            return MockResponse(success=False, error="Missing required parameter: Item")

        self._tables[table_name].append(item)

        return MockResponse(
            success=True,
            response={},
        )

    def create_table(self, table_name: str) -> None:
        """Create a table in the mock (for setup in demos and tests)."""
        self._tables[table_name] = []

    def seed(self, table_name: str, items: list[dict[str, Any]]) -> None:
        """Pre-populate a table with items (for demos and tests).

        Creates the table if it doesn't exist.
        """
        if table_name not in self._tables:
            self._tables[table_name] = []
        self._tables[table_name].extend(items)

    def _apply_filter(self, items: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
        """Simple filter: match items where any attribute equals any expression value."""
        attr_values = params.get("ExpressionAttributeValues", {})
        if not attr_values:
            return list(items)

        # Extract the actual values from DynamoDB type descriptors
        # e.g., {":dept": {"S": "engineering"}} → look for "engineering" in any field
        search_values = []
        for typed_value in attr_values.values():
            if isinstance(typed_value, dict):
                for v in typed_value.values():
                    search_values.append(v)

        if not search_values:
            return list(items)

        # Return items where any field value matches any search value
        filtered = []
        for item in items:
            for field_value in item.values():
                # Handle DynamoDB typed values: {"S": "value"}
                actual = field_value
                if isinstance(field_value, dict) and len(field_value) == 1:
                    actual = next(iter(field_value.values()))
                if actual in search_values:
                    filtered.append(item)
                    break

        return filtered
