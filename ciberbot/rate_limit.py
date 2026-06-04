"""Rate limit en memoria (sliding window por usuario)."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(1, int(per_minute))
        self._buckets: dict[int, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit(self, user_id: int) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            bucket = self._buckets[user_id]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.per_minute:
                return False
            bucket.append(now)
            return True
