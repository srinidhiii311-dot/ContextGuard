/**
 * frontend/lib/ws-client.js
 * Subscribes to the ContextGuard session event stream: /ws/sessions/:id
 */

class ContextGuardWSClient {
  constructor(sessionId, callbacks = {}) {
    this.sessionId = sessionId;
    this.callbacks = callbacks; // onEvent, onBlock, onPause, onResume, onComplete, onOpen, onClose
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnect = 5;
    this.connect();
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const url = `${protocol}//${host}/ws/sessions/${this.sessionId}`;

    try {
      this.ws = new WebSocket(url);
    } catch (err) {
      console.error("[WS] Connection failed:", err);
      return;
    }

    this.ws.onopen = () => {
      console.log(`[WS] Connected to session ${this.sessionId}`);
      this.reconnectAttempts = 0;
      if (this.callbacks.onOpen) this.callbacks.onOpen();
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'session_blocked') {
          if (this.callbacks.onBlock) this.callbacks.onBlock(data);
        } else if (data.type === 'session_paused') {
          if (this.callbacks.onPause) this.callbacks.onPause(data);
        } else if (data.type === 'session_resumed') {
          if (this.callbacks.onResume) this.callbacks.onResume(data);
        } else if (data.type === 'session_completed') {
          if (this.callbacks.onComplete) this.callbacks.onComplete(data);
        } else {
          // Standard browser event + verdict push
          if (this.callbacks.onEvent) this.callbacks.onEvent(data);
        }
      } catch (err) {
        console.error("[WS] Parse error:", err);
      }
    };

    this.ws.onclose = () => {
      if (this.callbacks.onClose) this.callbacks.onClose();
      if (this.reconnectAttempts < this.maxReconnect) {
        this.reconnectAttempts++;
        setTimeout(() => this.connect(), 1000 * this.reconnectAttempts);
      }
    };

    this.ws.onerror = (err) => {
      console.warn("[WS] Error:", err);
    };
  }

  close() {
    this.reconnectAttempts = this.maxReconnect;
    if (this.ws) {
      this.ws.close();
    }
  }
}

window.ContextGuardWSClient = ContextGuardWSClient;
