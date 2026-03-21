"""Mock S3 service — in-memory object storage."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentgate.mock_aws.base import MockResponse, MockServiceRegistry

logger = logging.getLogger(__name__)


@dataclass
class S3Object:
    """An object stored in the mock S3."""

    body: str
    content_type: str = "application/octet-stream"
    last_modified: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MockS3:
    """In-memory S3 mock supporting GetObject, PutObject, and DeleteObject."""

    def __init__(self) -> None:
        # Storage: {(bucket, key): S3Object}
        self._store: dict[tuple[str, str], S3Object] = {}

    def register(self, registry: MockServiceRegistry) -> None:
        """Register all S3 handlers with the service registry."""
        registry.register("s3:GetObject", self.get_object)
        registry.register("s3:PutObject", self.put_object)
        registry.register("s3:DeleteObject", self.delete_object)

    def get_object(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Retrieve an object from mock S3.

        Params: Bucket, Key
        """
        bucket = params.get("Bucket", "")
        key = params.get("Key", "")
        if not bucket or not key:
            return MockResponse(success=False, error="Missing required parameter: Bucket and Key")

        obj = self._store.get((bucket, key))
        if obj is None:
            return MockResponse(
                success=False,
                error=f"NoSuchKey: The specified key does not exist. Bucket={bucket}, Key={key}",
            )

        etag = hashlib.md5(obj.body.encode()).hexdigest()
        return MockResponse(
            success=True,
            response={
                "Body": obj.body,
                "ContentLength": len(obj.body),
                "ContentType": obj.content_type,
                "ETag": f'"{etag}"',
                "LastModified": obj.last_modified,
            },
        )

    def put_object(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Store an object in mock S3.

        Params: Bucket, Key, Body, ContentType (optional)
        """
        bucket = params.get("Bucket", "")
        key = params.get("Key", "")
        body = params.get("Body", "")
        if not bucket or not key:
            return MockResponse(success=False, error="Missing required parameter: Bucket and Key")

        content_type = params.get("ContentType", "application/octet-stream")
        obj = S3Object(body=body, content_type=content_type)
        self._store[(bucket, key)] = obj

        etag = hashlib.md5(body.encode()).hexdigest()
        return MockResponse(
            success=True,
            response={
                "ETag": f'"{etag}"',
            },
        )

    def delete_object(self, resource: str, params: dict[str, Any]) -> MockResponse:
        """Delete an object from mock S3.

        Params: Bucket, Key
        """
        bucket = params.get("Bucket", "")
        key = params.get("Key", "")
        if not bucket or not key:
            return MockResponse(success=False, error="Missing required parameter: Bucket and Key")

        self._store.pop((bucket, key), None)

        # Real S3 returns success even if the key didn't exist
        return MockResponse(
            success=True,
            response={
                "DeleteMarker": False,
            },
        )

    def seed(self, bucket: str, key: str, body: str, content_type: str = "application/octet-stream") -> None:
        """Pre-populate the mock with data (for demos and tests)."""
        self._store[(bucket, key)] = S3Object(body=body, content_type=content_type)
