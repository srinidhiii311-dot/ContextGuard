"""
backend/events/bus.py — WebSocket Event Broadcaster

Subscribes clients to /ws/sessions/{session_id} and streams real-time
event + verdict updates as the web agent executes.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, List, Set

from fastapi import WebSocket


class EventBus:
    """Session-scoped thread-safe WebSocket broadcaster."""

    def __init__(self) -> None:
        # Maps session_id -> list of active WebSocket connections
        self._subscribers: Dict[str, Set[WebSocket]] = {}
        self._lock = threading.Lock()

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            if session_id not in self._subscribers:
                self._subscribers[session_id] = set()
            self._subscribers[session_id].add(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket) -> None:
        with self._lock:
            if session_id in self._subscribers:
                self._subscribers[session_id].discard(websocket)
                if not self._subscribers[session_id]:
                    del self._subscribers[session_id]

    async def broadcast_to_session(self, session_id: str, message: Dict[str, Any]) -> None:
        """Async broadcast to all clients viewing a session."""
        payload = json.dumps(message)
        with self._lock:
            subscribers = list(self._subscribers.get(session_id, set()))

        dead: List[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(session_id, ws)

    def broadcast_sync(self, session_id: str, message: Dict[str, Any]) -> None:
        """Sync helper to broadcast across thread boundaries."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.broadcast_to_session(session_id, message))
            else:
                loop.run_until_complete(self.broadcast_to_session(session_id, message))
        except RuntimeError:
            pass


event_bus = EventBus()
