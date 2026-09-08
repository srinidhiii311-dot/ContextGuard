"""
backend/websocket/manager.py — Phase 3

Manages all active WebSocket connections and broadcasts events
to every connected dashboard client.

Every agent action, attack injection, and ContextGuard alert
is pushed here so the dashboard shows live status without polling.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, List

from fastapi import WebSocket


class WebSocketManager:
    """Thread-safe WebSocket connection manager."""

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Async broadcast to all connected clients."""
        payload = json.dumps(message)
        dead: List[WebSocket] = []
        with self._lock:
            targets = list(self._connections)

        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    def broadcast_sync(self, message: Dict[str, Any]) -> None:
        """
        Fire-and-forget broadcast callable from sync (non-async) code.
        Used by backend endpoints that are called from sync contexts.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.broadcast(message))
            else:
                loop.run_until_complete(self.broadcast(message))
        except RuntimeError:
            # No event loop in this thread — skip broadcast silently
            pass

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self._connections)


# Module-level singleton shared across the application
ws_manager = WebSocketManager()
