"""Local webapp bridge: stdlib-only HTTP server for the thread webapp.

Serves ``index.html`` / ``app.js`` / ``pairing.html`` statically and
exposes a tiny JSON API over the existing meshctl transport modules
(``boards``, ``bus``, ``contacts``, ``history``, ``local`` — imported
read-only, never edited). Single-owner: one ``EventBus`` owns every
attached port for the life of this process, exactly like the TUI and
the Tk app. No key handling here; pairing help is static text.

Run: ``python3 webapp/serve.py [--port 8077] [--no-history]``
then open http://localhost:8077/ in a browser.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent

# Ops the webapp may queue on an owned port. Pairing/crypto flows are
# untouched passthroughs (offer/proof/confirm/import only transport
# opaque records); SAS comparison stays a human step on the help page.
# The fixed +2dBm messaging path is the plain `send` op.
ALLOWED_OPS = {
    "status", "contacts", "ping", "time_set", "radio_set",
    "block", "unblock", "contact_delete",
    "pair_offer", "pair_proof", "pair_confirm", "pair_import",
}

class Bridge:
    """Owns ports via EventBus; drains events into history + backlog."""

    def __init__(self) -> None:
        from host.meshctl import boards as _boards
        from host.meshctl import bus as _bus
        self.bus = _bus.EventBus()
        self.known: dict[str, object] = {}
        self.info: dict[str, dict] = {}
        self.events: list[dict] = []
        self._cursor = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        for board in _boards.probe_all(timeout=5.0):
            self.known[board.serial] = board
            self.info[board.serial] = _snapshot(board)
            self.bus.attach(board.serial, board.device, board.label)
        self._pump = threading.Thread(target=self._drain, daemon=True)
        self._pump.start()

    # ---- state ---------------------------------------------------------
    def _append(self, item: dict) -> None:
        with self._lock:
            self._cursor += 1
            item["cursor"] = self._cursor
            self.events.append(item)
            del self.events[:-500]

    def _drain(self) -> None:
        from host.meshctl import contacts as _contacts
        from host.meshctl import history as _history
        from host.meshctl import local as _local

        while not self._stop.is_set():
            for event in self.bus.poll():
                board = self.known.get(event.board)
                tag = (getattr(board, "label", "") if board else event.board[:8]) or event.board[:8]
                if event.kind == "received":
                    name = None
                    if board is not None:
                        try:
                            name = _contacts.name_for_id(board.serial, event.contact_id)
                        except (ValueError, OSError, RuntimeError):
                            name = None
                    who = name or f"id{event.contact_id}"
                    if board is not None:
                        try:
                            conn = _history.open_history(_local.history_path_for(board.device))
                            try:
                                _history.record_message(
                                    conn, contact=who, direction="in",
                                    epoch=event.epoch, sequence=event.sequence,
                                    text=event.text)
                            finally:
                                conn.close()
                        except (ValueError, TypeError, OSError, RuntimeError):
                            pass  # DISABLED: live view still works
                    self._append({"type": "msg", "serial": event.board,
                                  "contact": who, "direction": "in",
                                  "text": event.text, "epoch": event.epoch,
                                  "sequence": event.sequence})
                elif event.kind == "reply":
                    try:
                        obj = json.loads(event.text)
                    except ValueError:
                        self._append({"type": "notice", "serial": event.board,
                                      "text": f"[{tag}] malformed reply"})
                        continue
                    result = obj.get("result", {}) if isinstance(obj, dict) else {}
                    if isinstance(result, dict) and (
                            "label" in result or "epoch" in result or "counters" in result):
                        info = self.info.setdefault(event.board, {})
                        for key in ("label", "epoch", "time_valid", "radio_enabled",
                                    "radio_available", "counters", "contacts"):
                            if key in result:
                                info[key] = result[key]
                        self._append({"type": "boards", "serial": event.board})
                    status = result.get("status", "") if isinstance(result, dict) else ""
                    if status in ("ACKNOWLEDGED", "UNCONFIRMED"):
                        self._append({"type": "tick", "serial": event.board,
                                      "status": status,
                                      "reply_id": obj.get("id") if isinstance(obj, dict) else None,
                                      "text": event.text[:200]})
                    elif isinstance(result, dict) and result.get("record_b64"):
                        rec = result["record_b64"]
                        self._append({"type": "notice", "serial": event.board,
                                      "text": f"[{tag}] pairing record ({len(rec)} chars); "
                                              "compare fingerprint aloud"})
                    elif status or event.text.strip() != "{}":
                        self._append({"type": "notice", "serial": event.board,
                                      "text": f"[{tag}] {event.text[:200]}"})
                else:
                    self._append({"type": "notice", "serial": event.board,
                                  "text": f"[{tag}] {event.text[:200]}"})
            time.sleep(0.1)

    def shutdown(self) -> None:
        self._stop.set()
        self.bus.detach_all()

    # ---- API helpers -----------------------------------------------------
    def board_list(self) -> list[dict]:
        from host.meshctl import contacts as _contacts

        out = []
        for serial, board in self.known.items():
            info = self.info.get(serial, {})
            counters = info.get("counters", getattr(board, "counters", {})) or {}
            contacts = info.get("contacts", getattr(board, "contacts", {})) or {}
            count = contacts.get("count", "?") if isinstance(contacts, dict) else "?"
            out.append({
                "serial": serial,
                "label": info.get("label", getattr(board, "label", "")) or serial[:8],
                "epoch": info.get("epoch", getattr(board, "epoch", 0)),
                "time_valid": info.get("time_valid", getattr(board, "time_valid", False)),
                "radio_enabled": info.get("radio_enabled", getattr(board, "radio_enabled", False)),
                "radio_available": info.get("radio_available",
                                            getattr(board, "radio_available", False)),
                "counters": counters,
                "contacts_count": count,
                "threads": _contacts.names_for(serial),
                "history_disabled": _history_disabled(),
            })
        return out

    def history_for(self, serial: str, contact: str, limit: int) -> list[dict]:
        from host.meshctl import history as _history
        from host.meshctl import local as _local

        board = self.known.get(serial)
        if board is None:
            raise KeyError("unknown board")
        try:
            limit = min(max(int(limit), 1), 200)
        except (TypeError, ValueError):
            limit = 50
        conn = _history.open_history(_local.history_path_for(board.device))
        try:
            rows = _history.recent_messages(conn, limit=200)
        finally:
            conn.close()
        out = [{"contact": c, "direction": d, "epoch": e, "sequence": s, "text": t}
               for c, d, e, s, t in rows if c == contact]
        return list(reversed(out[-limit:]))

    def events_since(self, cursor: int) -> tuple[int, list[dict]]:
        with self._lock:
            items = [e for e in self.events if e.get("cursor", 0) > cursor]
            return self._cursor, items

    def send(self, serial: str, contact: str, text: str) -> dict:
        from host.meshctl import contacts as _contacts
        from host.meshctl import history as _history
        from host.meshctl import local as _local

        board = self.known.get(serial)
        if board is None:
            raise KeyError("unknown board")
        if not text or len(text.encode("utf-8")) > 160:
            raise ValueError("text must be 1-160 UTF-8 bytes, never truncated")
        cid = _contacts.resolve_contact(serial, contact)
        if cid is None:
            raise ValueError(f"unknown contact '{contact}'")
        self.bus.request(serial, "send", {"contact_id": cid, "text": text}, timeout=60.0)
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
            try:
                _history.record_message(conn, contact=contact, direction="out",
                                        epoch=0, sequence=0, text=text)
            finally:
                conn.close()
        except (ValueError, TypeError, OSError, RuntimeError):
            pass
        return {"ok": True}

    def op(self, serial: str, op: str, params: dict | None) -> dict:
        if op not in ALLOWED_OPS:
            raise ValueError(f"op {op!r} not allowed from the webapp")
        if serial not in self.known:
            raise KeyError("unknown board")
        timeout = 10.0
        self.bus.request(serial, op, params or None, timeout=timeout)
        return {"ok": True}


def _snapshot(board: object) -> dict:
    return {
        "label": getattr(board, "label", ""),
        "epoch": getattr(board, "epoch", 0),
        "time_valid": getattr(board, "time_valid", False),
        "radio_enabled": getattr(board, "radio_enabled", False),
        "radio_available": getattr(board, "radio_available", False),
        "counters": dict(getattr(board, "counters", {}) or {}),
        "contacts": getattr(board, "contacts", {}) or {},
    }


def _history_disabled() -> bool:
    from host.meshctl import history as _history

    return bool(_history.DISABLED)


MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".png": "image/png"}


class Handler(BaseHTTPRequestHandler):
    bridge: Bridge | None = None

    def log_message(self, *args: object) -> None:
        pass  # quiet bench: errors go in JSON bodies, not the console

    def _json(self, code: int, obj: dict | list) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, name: str) -> None:
        path = HERE / name
        if path.suffix not in MIME or not path.is_file():
            self._json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MIME[path.suffix])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        assert self.bridge is not None
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path in ("/", "/index.html"):
            self._static("index.html")
        elif parsed.path == "/app.js":
            self._static("app.js")
        elif parsed.path in ("/pairing", "/pairing.html"):
            self._static("pairing.html")
        elif parsed.path == "/api/boards":
            self._json(200, {"ok": True, "boards": self.bridge.board_list()})
        elif parsed.path == "/api/events":
            try:
                cursor = int(query.get("cursor", ["0"])[0])
            except (TypeError, ValueError):
                cursor = 0
            latest, items = self.bridge.events_since(cursor)
            self._json(200, {"ok": True, "cursor": latest, "events": items})
        elif parsed.path == "/api/history":
            serial = query.get("serial", [""])[0]
            contact = query.get("contact", [""])[0]
            limit = query.get("limit", ["50"])[0]
            try:
                rows = self.bridge.history_for(serial, contact, limit)
            except KeyError:
                self._json(404, {"ok": False, "error": "unknown board"})
            except RuntimeError as exc:  # history.DISABLED gate
                self._json(200, {"ok": True, "disabled": True,
                                 "error": str(exc), "messages": []})
            except (ValueError, TypeError, OSError) as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            else:
                self._json(200, {"ok": True, "messages": rows})
        else:
            self._json(404, {"ok": False, "error": "NOT_FOUND"})

    def do_POST(self) -> None:
        assert self.bridge is not None
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            self._json(400, {"ok": False, "error": "bad JSON"})
            return
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "error": "bad JSON"})
            return
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/send":
                result = self.bridge.send(str(body.get("serial", "")),
                                          str(body.get("contact", "")),
                                          str(body.get("text", "")))
                self._json(200, result)
            elif parsed.path == "/api/op":
                params = body.get("params")
                result = self.bridge.op(str(body.get("serial", "")),
                                        str(body.get("op", "")),
                                        dict(params) if isinstance(params, dict) else None)
                self._json(200, result)
            else:
                self._json(404, {"ok": False, "error": "NOT_FOUND"})
        except KeyError as exc:
            self._json(404, {"ok": False, "error": str(exc)})
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the local mesh webapp")
    parser.add_argument("--port", type=int, default=8077)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--no-history", action="store_true",
                        help="do not read/write plaintext message history")
    args = parser.parse_args(argv)

    import sys as _sys
    _sys.path.insert(0, str(HERE.parent))
    from host.meshctl import history as _history

    _history.DISABLED = bool(args.no_history)

    bridge = Bridge()
    Handler.bridge = bridge
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mesh webapp: http://{args.host}:{args.port}/ "
          f"({len(bridge.known)} station(s))", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        bridge.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
