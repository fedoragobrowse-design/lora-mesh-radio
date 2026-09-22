"""Terminal TUI for the mesh: Meshtastic-style threads over the Pico fleet.

Layout: sidebar conversations (board sections + contact threads with
unread badges) -> thread pane (message bubbles grouped by contact,
backed by history SQLite reads) -> input bar. Per-message states:
queued (◷) / sent (✓) / ACKED (✓✓) / failed (✗). The header shows
board label, epoch/time_valid, radio on/off, and last counters.

Boards attach on start and stay owned until quit; `/quit` detaches all.

Keys: Tab cycles boards, 1/2/3 jump to A/B/C, Up/Down switch thread,
F2 opens the contact picker (Up/Down + Enter, Esc cancels), typing `/`
opens the command palette (Up/Down + Enter), `/to NAME` targets a
thread, `/block NAME` + `/unblock NAME` + `/delete NAME` manage slots,
`/radio on|off` (fixed +2dBm/SF7/BW500 profile, display-only),
`/pair offer|proof|confirm` exports a pairing record, `/find TEXT`
searches threads + history, `/all TEXT` broadcasts via every board, `/debug`
toggles raw-event view, `/status`, `/contacts`, `/settings [KEY]` (read-only),
`/quit`.
Plain typing sends to the current thread.
"""
from __future__ import annotations

import argparse
import curses
import time

from . import boards as _boards
from . import bus as _bus
from . import contacts as _contacts
from . import history as _history
from . import local as _local

PALETTE = {
    "desk": 232,      # near-black bench top
    "panel": 235,     # panel felt
    "brass": 178,     # brass dial markings
    "amber": 214,     # outbound / active target
    "moss": 107,      # inbound traffic
    "fault": 167,     # faults red
    "paper": 230,     # logbook paper
    "dim": 243,       # quiet annotations
}

HELP_LINES = [
    "Tab board · 1/2/3 A/B/C · Up/Down thread · type + Enter sends · F2 contacts · /quit leaves",
]

# Shown in the thread pane until the first conversation exists.
FIRST_RUN_HELP = [
    "No conversations yet — here is the 30-second start:",
    "",
    "  1. Press F2 to pick a contact, or type /to NAME + Enter",
    "  2. Type a message + Enter to send it",
    "     ◷ queued · ✓ sent · ✓✓ ACKED · ✗ not delivered",
    "  3. Tab switches board (A/B/C); Up/Down switches thread",
    "",
    "Pairing a new contact: /pair offer here, import the QR on the",
    "other board, then compare the SAS fingerprints aloud on BOTH",
    "sides before confirming. Radio stays on the fixed +2dBm profile.",
]

# Per-message state ticks (ACKNOWLEDGED -> ✓✓, UNCONFIRMED -> ✗).
TICKS = {"queued": "◷", "sent": "✓", "acked": "✓✓", "failed": "✗", "in": "←"}


class Msg:
    """One bubble in a thread."""

    __slots__ = ("direction", "text", "state")

    def __init__(self, direction: str, text: str, state: str) -> None:
        self.direction = direction  # "in" | "out"
        self.text = text
        self.state = state  # "in" | "queued" | "sent" | "acked" | "failed"


class Thread:
    """One (board, contact) conversation."""

    __slots__ = ("contact", "msgs", "unread")

    def __init__(self, contact: str) -> None:
        self.contact = contact
        self.msgs: list[Msg] = []
        self.unread = 0

    def push(self, msg: Msg) -> None:
        self.msgs.append(msg)
        del self.msgs[:-200]


class Tui:
    """Curses state: sidebar threads, thread pane, input. Bus pumps events in."""

    def __init__(self, stdscr: object, known: dict[str, object]) -> None:
        self.stdscr = stdscr
        self.bus = _bus.EventBus()
        self.known: dict[str, _boards.Board] = dict(known)
        self.order: list[str] = []
        self.threads: dict[str, dict[str, Thread]] = {}
        self.sel_board = 0
        self.sel_thread: str | None = None
        self.info: dict[str, dict] = {}  # serial -> live header facts
        self.log: list[tuple[str, str]] = []  # debug/notice overflow
        self.input = ""
        self.picker = -1
        self.palette = -1
        self.debug = False
        self.status = "scanning…"
        # Unique send-op accounting: one entry per send call so identical
        # retexts never collide. Key is a local op id; the value carries
        # the predicted bus request id (EventBus numbers each board's
        # requests 1,2,3… in call order and the TUI owns every port, so a
        # local per-board counter stays in sync) for exact reply matching.
        self.pending_sends: dict[int, tuple[str, str, str, int, int | None]] = {}
        self._send_seq = 0
        self._bus_seq: dict[str, int] = {}
        for serial, board in self.known.items():
            assert isinstance(board, _boards.Board)
            self.bus.attach(board.serial, board.device, board.label)
            self.order.append(serial)
            self.threads[serial] = {}
            self.info[serial] = _snapshot(board)
            self._load_history(board)
        if not self.order:
            self.status = "no boards attached (check USB)"
        else:
            self._fix_selection()

    # ---- thread model --------------------------------------------------
    def board(self) -> _boards.Board | None:
        """Current board or None."""
        if not self.order:
            return None
        return self.known.get(self.order[self.sel_board % len(self.order)])

    def serial(self) -> str | None:
        board = self.board()
        return board.serial if board is not None else None

    def thread_names(self, serial: str) -> list[str]:
        """Mapped contacts first, then live-only peers, stable order."""
        names = [n for n in _contacts.names_for(serial)
                 if n not in self.threads.get(serial, {})]
        ordered = list(self.threads.get(serial, {}).keys()) + names
        for name in names:
            self.threads.setdefault(serial, {})[name] = Thread(name)
        return ordered

    def get_thread(self, serial: str, contact: str) -> Thread:
        return self.threads.setdefault(serial, {}).setdefault(contact, Thread(contact))

    def flat_threads(self) -> list[tuple[str, str]]:
        """Every (serial, contact) row in sidebar order."""
        rows = []
        for serial in self.order:
            for name in self.thread_names(serial):
                rows.append((serial, name))
        return rows

    def current_thread(self) -> Thread | None:
        serial = self.serial()
        if serial is None or self.sel_thread is None:
            return None
        return self.threads.get(serial, {}).get(self.sel_thread)

    def select(self, serial: str, contact: str | None) -> None:
        """Select a board + thread; opening a thread clears its badge."""
        if serial in self.order:
            self.sel_board = self.order.index(serial)
        self.sel_thread = contact
        if contact is not None:
            thread = self.threads.get(serial, {}).get(contact)
            if thread is not None:
                thread.unread = 0

    def _fix_selection(self) -> None:
        rows = self.flat_threads()
        if not rows:
            self.sel_thread = None
            return
        serial = self.serial()
        if self.sel_thread is None or (serial, self.sel_thread) not in rows:
            self.sel_board = 0
            first = [c for s, c in rows if s == self.order[0]]
            self.sel_thread = first[0] if first else rows[0][1]
            self.sel_board = self.order.index(rows[0][0]) if not first else 0

    def cycle_board(self, step: int = 1) -> None:
        if not self.order:
            return
        self.sel_board = (self.sel_board + step) % len(self.order)
        serial = self.order[self.sel_board]
        names = self.thread_names(serial)
        self.select(serial, names[0] if names else None)

    def step_thread(self, step: int) -> None:
        rows = self.flat_threads()
        if not rows:
            return
        serial = self.serial()
        try:
            idx = rows.index((serial, self.sel_thread)) if self.sel_thread else -1
        except ValueError:
            idx = -1
        nxt = rows[(idx + step) % len(rows)]
        self.select(*nxt)

    def names(self, board: _boards.Board) -> list[str]:
        """Mapped names for this board (serial-keyed, arbitrary labels)."""
        return self.thread_names(board.serial)

    def target(self, board: _boards.Board) -> str:
        """Current send target name for this board (selected thread)."""
        if board.serial == self.serial() and self.sel_thread:
            return self.sel_thread
        names = self.names(board)
        return names[0] if names else ""

    def complete(self, board: _boards.Board, frag: str) -> list[str]:
        """Mapped names starting with `frag` (case-insensitive)."""
        frag = frag.lower()
        return [n for n in self.names(board) if n.lower().startswith(frag)]

    # ---- history ---------------------------------------------------------
    def _load_history(self, board: _boards.Board) -> None:
        """Seed threads from the per-port history SQLite (oldest-first)."""
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
        except (ValueError, TypeError, OSError, RuntimeError):
            return  # DISABLED (--no-history): live traffic only, no artifact
        try:
            rows = _history.recent_messages(conn, limit=200)
        except (ValueError, TypeError, OSError, RuntimeError):
            try:
                conn.close()
            except Exception:
                pass
            return
        try:
            for contact, direction, _epoch, _seq, text in reversed(rows):
                thread = self.get_thread(board.serial, str(contact))
                state = "in" if direction == "in" else "acked"
                thread.msgs.append(Msg(direction, str(text)[:300], state))
                del thread.msgs[:-200]
        finally:
            conn.close()

    def _remember(self, board: _boards.Board, contact: str, direction: str,
                  text: str, epoch: int = 0, sequence: int = 0) -> None:
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
            try:
                _history.record_message(conn, contact=contact, direction=direction,
                                        epoch=epoch, sequence=sequence, text=text)
            finally:
                conn.close()
        except (ValueError, TypeError, OSError, RuntimeError):
            pass  # DISABLED or unwritable: live view still works

    # ---- bus ---------------------------------------------------------------
    def _request(self, serial: str, op: str, params: dict | None, timeout: float) -> int | None:
        """Bus request that predicts the board's reply id for send matching."""
        nxt = self._bus_seq.get(serial, 0) + 1
        self._bus_seq[serial] = nxt
        self.bus.request(serial, op, params, timeout=timeout)
        return nxt

    def _parse_reply(self, text: str) -> dict:
        """Best-effort decode of a bus `reply` payload ({} on garbage)."""
        try:
            import json as _json
            obj = _json.loads(text)
        except ValueError:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _match_op(self, serial: str, reply_id: object) -> int | None:
        """Oldest pending send op for `serial` with the reply id (None if unknown)."""
        if type(reply_id) is int:
            for op_id in sorted(self.pending_sends):
                s, _name, _text, _count, bus_id = self.pending_sends[op_id]
                if s == serial and bus_id == reply_id:
                    return op_id
        return None

    def _oldest_op(self, serial: str) -> int | None:
        """Oldest pending send op for `serial` (reply-id fallback)."""
        for op_id in sorted(self.pending_sends):
            if self.pending_sends[op_id][0] == serial:
                return op_id
        return None

    def _set_state(self, serial: str, contact: str, text: str,
                   old: str, new: str) -> None:
        thread = self.threads.get(serial, {}).get(contact)
        if thread is None:
            return
        for msg in reversed(thread.msgs):
            if msg.direction == "out" and msg.text == text and msg.state == old:
                msg.state = new
                return

    def palette_items(self) -> list[str]:
        """Slash commands for the inline palette."""
        return [
            "/to NAME", "/status", "/contacts", "/settings [KEY]", "/radio on", "/radio off",
            "/pair offer", "/pair proof", "/pair confirm",
            "/block NAME", "/unblock NAME", "/delete NAME",
            "/debug", "/find TEXT", "/all TEXT", "/quit",
        ]

    def say(self, text: str, style: str = "paper") -> None:
        """Append one overflow log line, capped (debug/notice view)."""
        self.log.append((style, text[:300]))
        del self.log[:-500]

    def thread_msg(self, serial: str, peer: str, text: str, style: str,
                   direction: str = "out", state: str = "sent") -> None:
        """Append a bubble to one thread (no shared-log mixing)."""
        thread = self.get_thread(serial, peer)
        thread.push(Msg(direction, text[:300], state))
        if serial != self.serial() or peer != self.sel_thread:
            thread.unread += 1

    def pump(self) -> None:
        """Drain the bus into threads with contact names resolved."""
        for event in self.bus.poll():
            board = self.known.get(event.board)
            tag = (board.label if board else event.board[:8]) or event.board[:8]
            if event.kind == "received":
                name = None
                if board is not None:
                    try:
                        name = _contacts.name_for_id(board.serial, event.contact_id)
                    except (ValueError, OSError, RuntimeError):
                        name = None
                who = name or f"id{event.contact_id}"
                self.thread_msg(event.board, who, event.text, "moss",
                                direction="in", state="in")
                if self.sel_thread is None and event.board == self.serial():
                    self.select(event.board, who)
                elif event.board == self.serial() and who == self.sel_thread:
                    thread = self.threads.get(event.board, {}).get(who)
                    if thread is not None:
                        thread.unread = 0
                if board is not None:
                    self._remember(board, who, "in", event.text,
                                   epoch=event.epoch, sequence=event.sequence)
            elif event.kind == "reply":
                obj = self._parse_reply(event.text)
                result = obj.get("result", {}) if isinstance(obj, dict) else {}
                if isinstance(result, dict) and isinstance(result.get("settings"), list):
                    # Read-only settings display (contract: TUI never sends
                    # settings_set). One line per entry incl. clamp/applied state.
                    for entry in result["settings"]:
                        if not isinstance(entry, dict):
                            continue
                        key = entry.get("key", "?")
                        value = entry.get("value", "?")
                        applied = entry.get("applied", True)
                        ro = " ro" if entry.get("readonly") else ""
                        pend = "" if applied else " (pending radio-on)"
                        self.say(f"[{tag}] {key}={value}{ro}{pend}", "paper")
                    continue
                if isinstance(result, dict) and result.get("record_b64"):
                    rec = result["record_b64"]
                    self.say(f"[{tag}] pairing record ({len(rec)} chars):", "amber")
                    self.say(rec[:120], "paper")
                    if len(rec) > 120:
                        self.say(rec[120:240], "paper")
                    self.say("full text in history file; compare fingerprint aloud", "dim")
                    continue
                if isinstance(result, dict) and (
                        "label" in result or "epoch" in result or "counters" in result):
                    # status/contacts reply: refresh the header facts.
                    info = self.info.setdefault(event.board, {})
                    for key in ("label", "epoch", "time_valid", "radio_enabled",
                                "radio_available", "counters", "contacts"):
                        if key in result:
                            info[key] = result[key]
                    if isinstance(result.get("contacts"), dict):
                        self.thread_names(event.board)
                    if not self.debug:
                        continue
                    self.say(f"[{tag}] reply: {event.text[:160]}", "dim")
                    continue
                if "ACKNOWLEDGED" in event.text:
                    op_id = self._match_op(event.board, obj.get("id"))
                    if op_id is None:
                        op_id = self._oldest_op(event.board)
                    if op_id is not None:
                        s, name, text, _count, _bus = self.pending_sends.pop(op_id)
                        self._set_state(s, name, text, "sent", "acked")
                elif "UNCONFIRMED" in event.text:
                    op_id = self._match_op(event.board, obj.get("id"))
                    if op_id is None:
                        op_id = self._oldest_op(event.board)
                    if op_id is not None:
                        s, name, text, _count, _bus = self.pending_sends.pop(op_id)
                        self._set_state(s, name, text, "sent", "failed")
                        self._set_state(s, name, text, "queued", "failed")
                        self.say(f"[{tag} → {name}] ✗ not delivered (no ACK)", "fault")
                    elif self.debug:
                        self.say(f"[{tag}] reply: {event.text[:160]}", "dim")
                elif '"error":"BUSY"' in event.text.replace(" ", "") or '"error":"CHANNEL_BUSY"' in event.text.replace(" ", ""):
                    op_id = self._match_op(event.board, obj.get("id"))
                    if op_id is None:
                        op_id = self._oldest_op(event.board)
                    if op_id is None:
                        if self.debug:
                            self.say(f"[{tag}] reply: {event.text[:160]}", "dim")
                    elif self.retry_send(event.board, event.text, op_id):
                        s, name, text, count, _bus = self.pending_sends[op_id]
                        self._set_state(s, name, text, "queued", "queued")
                        self.say(f"[{tag}] … busy, retry {count}/2", "dim")
                    else:
                        entry = self.pending_sends.pop(op_id, None)
                        if entry is not None:
                            s, name, text, _count, _bus = entry
                            self._set_state(s, name, text, "queued", "failed")
                            self._set_state(s, name, text, "sent", "failed")
                elif self.debug:
                    self.say(f"[{tag}] reply: {event.text[:160]}", "dim")
            elif event.kind == "error":
                self.say(f"[{tag}] {event.text[:160]}", "fault")
            else:
                self.say(f"[{tag}] {event.text[:160]}", "dim")

    def retry_send(self, serial: str, reply_text: str, op_id: int) -> bool:
        """Retry one BUSY-stale send op, max 2 attempts (entry kept for reply)."""
        entry = self.pending_sends.get(op_id)
        if entry is None:
            return False
        s, name, text, count, _bus = entry
        if s != serial:
            return False
        if count >= 2:
            return False
        cid = _contacts.resolve_contact(serial, name)
        if cid is None:
            return False
        bus_id = self._request(serial, "send", {"contact_id": cid, "text": text}, timeout=60.0)
        self.pending_sends[op_id] = (s, name, text, count + 1, bus_id)
        self.say(f"[retry {count + 1}] {name}: {text}", "amber")
        return True

    def send_current(self) -> None:
        """Send the input line to the current thread."""
        text = self.input
        self.input = ""
        if not text.strip():
            return
        board = self.board()
        if board is None:
            self.say("no board selected", "fault")
            return
        name = self.target(board)
        if not name:
            self.say("no thread: F2 or /to NAME first (see help above)", "fault")
            return
        cid = _contacts.resolve_contact(board.serial, name)
        if cid is None:
            self.say(f"unknown contact '{name}'", "fault")
            return
        bus_id = self._request(board.serial, "send",
                               {"contact_id": cid, "text": text}, timeout=60.0)
        self._send_seq += 1
        self.pending_sends[self._send_seq] = (board.serial, name, text, 0, bus_id)
        self.thread_msg(board.serial, name, text, "amber",
                        direction="out", state="queued")
        # queued -> sent once the firmware accepts the frame (the ACKED
        # tick lands later via the ACKNOWLEDGED reply).
        self._set_state(board.serial, name, text, "queued", "sent")
        self.select(board.serial, name)
        self._remember(board, name, "out", text)

    def send_all(self, text: str) -> None:
        """Fan one line out to every board's current thread."""
        if not text.strip():
            self.say("usage: /all TEXT", "fault")
            return
        if not self.order:
            self.say("no board selected", "fault")
            return
        for serial in list(self.order):
            board = self.known.get(serial)
            if board is None:
                continue
            name = self.target(board)
            if not name:
                self.say(f"[{board.label or serial[:8]}] no thread: /to NAME first", "fault")
                continue
            cid = _contacts.resolve_contact(serial, name)
            if cid is None:
                self.say(f"[{board.label or serial[:8]}] unknown contact '{name}'", "fault")
                continue
            bus_id = self._request(serial, "send",
                                   {"contact_id": cid, "text": text}, timeout=60.0)
            self._send_seq += 1
            self.pending_sends[self._send_seq] = (serial, name, text, 0, bus_id)
            self.thread_msg(serial, name, text, "amber",
                            direction="out", state="sent")
            self._remember(board, name, "out", text)

    def find_history(self, needle: str) -> None:
        """Search local histories + live threads for `needle` (case-insensitive)."""
        needle = needle.strip()
        if not needle:
            self.say("usage: /find TEXT", "fault")
            return
        want = needle.lower()
        hits: list[tuple[str, str]] = []
        for serial in self.order:
            board = self.known.get(serial)
            tag = (board.label if board else serial[:8]) or serial[:8]
            for peer, thread in self.threads.get(serial, {}).items():
                for msg in thread.msgs:
                    if want in msg.text.lower():
                        hits.append(("moss", f"[{tag} · {peer}] {msg.text}"))
            try:
                if board is None:
                    continue
                conn = _history.open_history(_local.history_path_for(board.device))
                try:
                    for contact, direction, _epoch, _seq, text in _history.recent_messages(conn, limit=200):
                        if want in str(text).lower() or want in str(contact).lower():
                            arrow = "←" if direction == "in" else "→"
                            hits.append(("paper", f"[{tag} {arrow} {contact}] {text}"))
                finally:
                    conn.close()
            except (ValueError, TypeError, OSError, RuntimeError):
                pass
        if not hits:
            self.say(f"no match for '{needle}'", "dim")
            return
        self.say(f"— {len(hits)} match(es) for '{needle}' —", "amber")
        for style, line in hits[-20:]:
            self.say(line, style)

    def command(self, line: str) -> bool:
        """Run one `/` command. Returns False to quit."""
        cmd, _, rest = line[1:].partition(" ")
        board = self.board()
        if cmd == "quit":
            return False
        if cmd == "to":
            if board is None or not rest.strip():
                self.say("usage: /to NAME", "fault")
            elif not _contacts.valid_name(rest.strip()):
                self.say("name must be 1-32 non-blank chars", "fault")
            else:
                name = rest.strip()
                self.get_thread(board.serial, name)
                self.select(board.serial, name)
                self.say(f"thread: {name}", "amber")
        elif cmd in ("block", "unblock", "delete"):
            if board is None or not rest.strip():
                self.say(f"usage: /{cmd} NAME", "fault")
            else:
                cid = _contacts.resolve_contact(board.serial, rest.strip())
                if cid is None:
                    self.say(f"unknown contact '{rest.strip()}'", "fault")
                else:
                    op = "contact_delete" if cmd == "delete" else cmd
                    self._request(board.serial, op, {"contact_id": cid}, timeout=10.0)
                    self.say(f"{cmd}: {rest.strip()} (id {cid})", "amber")
        elif cmd == "radio" and rest.strip() in ("on", "off"):
            if board is not None:
                self._request(board.serial, "radio_set",
                              {"enabled": rest.strip() == "on"}, timeout=10.0)
        elif cmd in ("status", "contacts"):
            if board is not None:
                self._request(board.serial, cmd, None, timeout=10.0)
                self.say(f"{cmd}: reply updates the header/sidebar", "dim")
        elif cmd == "settings":
            # Read-only display only (TUI never sends settings_set).
            if board is not None:
                arg = rest.strip()
                self._request(board.serial, "settings_get",
                              {"key": arg} if arg else None, timeout=10.0)
        elif cmd == "debug":
            self.debug = not self.debug
            self.say(f"debug {'on' if self.debug else 'off'}", "amber")
        elif cmd == "pair" and rest.strip() in ("offer", "proof", "confirm"):
            if board is not None:
                op = {"offer": "pair_offer", "proof": "pair_proof",
                      "confirm": "pair_confirm"}[rest.strip()]
                self._request(board.serial, op, None, timeout=15.0)
                self.say(f"pair {rest.strip()}: reply lands below; compare fingerprint aloud", "amber")
        elif cmd == "find":
            self.find_history(rest)
        elif cmd == "all":
            self.send_all(rest)
        else:
            self.say(f"unknown command /{cmd}", "fault")
        return True

    # ---- drawing -------------------------------------------------------------
    def header_text(self) -> str:
        board = self.board()
        if board is None:
            return "— no board —"
        info = self.info.get(board.serial, {})
        label = info.get("label", board.label) or "?"
        epoch = info.get("epoch", board.epoch)
        tvalid = info.get("time_valid", board.time_valid)
        radio = info.get("radio_enabled", board.radio_enabled)
        counters = info.get("counters", board.counters) or {}
        tx = counters.get("tx_ok", counters.get("tx", "?"))
        rx = counters.get("rx_ok", counters.get("rx", "?"))
        contact = self.sel_thread or "no thread"
        return (f"{label} → {contact} · epoch {epoch} "
                f"{'⏱ok' if tvalid else '⏱--'} · radio {'ON' if radio else 'OFF'} "
                f"· tx {tx}/rx {rx}")

    def draw(self) -> None:
        """Paint sidebar, thread pane, input. Plain curses, no flicker tricks."""
        stdscr = self.stdscr
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        side_w = 26
        # Sidebar: board sections + threads with unread badges.
        row = 1
        for i, serial in enumerate(self.order):
            if row >= h - 3:
                break
            board = self.known.get(serial)
            info = self.info.get(serial, {})
            label = info.get("label", getattr(board, "label", "")) or serial[:8]
            active = serial == self.serial()
            try:
                stdscr.addstr(row, 1, f"{'●' if active else '○'} {label}"[: side_w - 1],
                              curses.color_pair(3) if active else curses.color_pair(2))
            except curses.error:
                pass
            row += 1
            for name in self.thread_names(serial):
                if row >= h - 3:
                    break
                thread = self.threads[serial][name]
                badge = f" ({thread.unread})" if thread.unread else ""
                line = f"  {name}{badge}"[: side_w - 1]
                selected = active and name == self.sel_thread
                try:
                    stdscr.addstr(row, 1, line,
                                  curses.color_pair(3) | curses.A_REVERSE if selected
                                  else curses.color_pair(4 if thread.unread else 6))
                except curses.error:
                    pass
                row += 1
            if not self.threads.get(serial):
                try:
                    stdscr.addstr(row, 1, "  (F2: add contact)"[: side_w - 1],
                                  curses.color_pair(6))
                except curses.error:
                    pass
                row += 1
        # Thread pane header + divider.
        try:
            stdscr.addstr(0, side_w + 2, self.header_text()[: w - side_w - 3],
                          curses.color_pair(2))
            stdscr.vline(0, side_w, curses.ACS_VLINE, h - 2)
            stdscr.hline(h - 3, side_w + 1, curses.ACS_HLINE, w - side_w - 1)
        except curses.error:
            pass
        thread = self.current_thread()
        if thread is None and not self.log:
            lines = FIRST_RUN_HELP if self.flat_threads() == [] else [
                "Pick a thread on the left (Up/Down), or F2 for contacts."]
            for i, text in enumerate(lines[-(h - 5):]):
                try:
                    stdscr.addstr(1 + i, side_w + 2, text[: w - side_w - 3],
                                  curses.color_pair(6 if text.startswith("  ") or not text else 1))
                except curses.error:
                    pass
        else:
            bubbles: list[tuple[str, str]] = []
            if thread is not None:
                for msg in thread.msgs[-(h - 5):]:
                    tick = TICKS.get(msg.state, "?")
                    if msg.direction == "in":
                        bubbles.append(("moss", f"← {msg.text}"))
                    else:
                        bubbles.append(("amber", f"  {msg.text} {tick}"))
            else:
                bubbles = [(style, text) for style, text in self.log[-(h - 5):]]
            if self.debug and self.log and thread is not None:
                bubbles += [("dim", f"… {text}") for _s, text in self.log[-3:]]
            styles = {"amber": 3, "moss": 4, "fault": 5, "paper": 1, "dim": 6}
            for i, (style, text) in enumerate(bubbles[-(h - 5):]):
                try:
                    stdscr.addstr(1 + i, side_w + 2, text[: w - side_w - 3],
                                  curses.color_pair(styles.get(style, 1)))
                except curses.error:
                    pass
        # Picker / palette popups above the input line.
        brow = h - 4
        board = self.board()
        if self.picker >= 0 and board is not None:
            for i, name in enumerate(self.names(board)):
                if brow - i < 1:
                    break
                try:
                    stdscr.addstr(brow - i, side_w + 2,
                                  f"{'▸' if i == self.picker % max(len(self.names(board)), 1) else ' '} {name}"[: w - side_w - 3],
                                  curses.color_pair(3) if i == self.picker % max(len(self.names(board)), 1) else curses.color_pair(6))
                except curses.error:
                    pass
        elif self.palette >= 0:
            items = [c for c in self.palette_items() if self.input[1:].lower() in c.lower()]
            for i, item in enumerate(items[:8]):
                if brow - i < 1:
                    break
                try:
                    stdscr.addstr(brow - i, side_w + 2,
                                  f"{'▸' if i == self.palette % max(len(items), 1) else ' '} {item}"[: w - side_w - 3],
                                  curses.color_pair(3) if i == self.palette % max(len(items), 1) else curses.color_pair(6))
                except curses.error:
                    pass
        # Input + help.
        try:
            stdscr.addstr(h - 2, side_w + 2, ("> " + self.input)[-(w - side_w - 3):],
                          curses.color_pair(1))
            stdscr.addstr(h - 1, 1, HELP_LINES[0][: w - 2], curses.color_pair(6))
        except curses.error:
            pass
        try:
            stdscr.move(h - 2, min(side_w + 4 + len(self.input), w - 1))
        except curses.error:
            pass
        stdscr.refresh()


def _snapshot(board: _boards.Board) -> dict:
    """Header facts from a probe (live status replies refresh these)."""
    return {
        "label": board.label,
        "epoch": board.epoch,
        "time_valid": board.time_valid,
        "radio_enabled": board.radio_enabled,
        "radio_available": board.radio_available,
        "counters": dict(board.counters),
        "contacts": board.contacts,
    }


def _scan() -> dict[str, _boards.Board]:
    """Probe attached boards into serial-keyed map."""
    try:
        found = _boards.probe_all()
    except OSError:
        return {}
    return {b.serial: b for b in found}


def _run(stdscr: object, known: dict) -> int:
    curses.start_color()
    curses.use_default_colors()
    for n, name in ((1, "paper"), (2, "brass"), (3, "amber"),
                    (4, "moss"), (5, "fault"), (6, "dim")):
        fg = {"paper": PALETTE["paper"], "brass": PALETTE["brass"],
              "amber": PALETTE["amber"], "moss": PALETTE["moss"],
              "fault": PALETTE["fault"], "dim": PALETTE["dim"]}[name]
        try:
            curses.init_pair(n, fg, PALETTE["desk"])
        except curses.error:
            pass
    try:
        stdscr.bkgd(" ", curses.color_pair(1))
    except curses.error:
        pass
    tui = Tui(stdscr, known)
    # `known` already holds the pre-entry scan; status counts stations.
    tui.status = f"{len(tui.order)} station(s)" if tui.order else "no boards"
    stdscr.nodelay(True)
    stdscr.keypad(True)
    running = True
    while running:
        tui.pump()
        tui.draw()
        try:
            key = stdscr.getch()
        except curses.error:
            key = -1
        if key == -1:
            time.sleep(0.05)
            continue
        if tui.picker >= 0:
            board = tui.board()
            names = tui.names(board) if board is not None else []
            if key in (27,):  # Esc cancels
                tui.picker = -1
            elif key in (curses.KEY_UP,) and names:
                tui.picker = (tui.picker - 1) % len(names)
            elif key in (curses.KEY_DOWN,) and names:
                tui.picker = (tui.picker + 1) % len(names)
            elif key in (curses.KEY_ENTER, 10, 13) and board is not None and names:
                name = names[tui.picker % len(names)]
                tui.select(board.serial, name)
                tui.say(f"thread: {name}", "amber")
                tui.picker = -1
            elif key in (curses.KEY_F2, 27):
                tui.picker = -1
            continue
        if key in (curses.KEY_F2,):
            board = tui.board()
            if board is not None and tui.names(board):
                tui.picker = 0
            else:
                tui.say("no contacts yet: /to NAME to start one", "fault")
        elif key in (ord("1"), ord("2"), ord("3")) and not tui.input:
            want = "ABC"[key - ord("1")]
            for i, s in enumerate(tui.order):
                if (tui.known[s].label or "?") == want:
                    tui.sel_board = i
                    names = tui.thread_names(s)
                    tui.select(s, names[0] if names else None)
                    break
        elif key in (curses.KEY_UP, curses.KEY_DOWN) and not (
                tui.input.startswith("/")):
            # Arrows switch thread (Up/Down); palette owns them for `/`.
            tui.step_thread(-1 if key == curses.KEY_UP else 1)
        elif key in (curses.KEY_LEFT, curses.KEY_RIGHT) and not tui.input:
            tui.step_thread(-1 if key == curses.KEY_LEFT else 1)
        elif key == 9:  # Tab: complete partial name, else cycle boards
            board = tui.board()
            frag = tui.input[3:] if tui.input.startswith("/to ") else tui.input
            matches = tui.complete(board, frag.strip()) if board is not None and frag.strip() else []
            if len(matches) == 1:
                tui.input = ("/to " if tui.input.startswith("/") else "") + matches[0]
                tui.picker = -1
            elif matches:
                tui.picker = 0
                tui.say("Tab: " + ", ".join(matches), "dim")
            elif tui.order:
                tui.cycle_board()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            tui.input = tui.input[:-1]
            tui.palette = 0 if tui.input.startswith("/") else -1
        elif key in (curses.KEY_ENTER, 10, 13):
            if tui.palette >= 0 and tui.input.startswith("/"):
                items = [c for c in tui.palette_items() if tui.input[1:].lower() in c.lower()]
                if items:
                    tui.input = items[tui.palette % len(items)]
                    tui.palette = -1
                    continue
            tui.palette = -1
            line = tui.input
            tui.input = ""
            if line.startswith("/"):
                running = tui.command(line)
            else:
                tui.input = line
                tui.send_current()
        elif key in (curses.KEY_UP,) and tui.input.startswith("/"):
            items = [c for c in tui.palette_items() if tui.input[1:].lower() in c.lower()]
            if items:
                tui.palette = (tui.palette - 1) % len(items) if tui.palette >= 0 else 0
        elif key in (curses.KEY_DOWN,) and tui.input.startswith("/"):
            items = [c for c in tui.palette_items() if tui.input[1:].lower() in c.lower()]
            if items:
                tui.palette = (tui.palette + 1) % len(items) if tui.palette >= 0 else 0
        elif 32 <= key <= 126:
            if len(tui.input) < 160:
                tui.input += chr(key)
            tui.palette = 0 if tui.input.startswith("/") else -1
    tui.bus.detach_all()
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Entry: scan boards, enter curses, own ports until quit."""
    _history.DISABLED = bool(getattr(args, "no_history", False))
    known = _scan()
    if not known:
        print("meshctl: no boards found (check USB)", flush=True)
        return 1
    import functools

    try:
        return curses.wrapper(functools.partial(_run, known=known))
    except KeyboardInterrupt:
        # Ctrl-C is a normal exit from the console, not a crash.
        return 0
