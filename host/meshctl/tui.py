"""Terminal TUI for the mesh: board roster, contacts, live traffic, send box.

Chat console: left column is the station roster (boards by label), center
is the traffic log (inbound moss green, outbound amber, faults red), top
is the `BOARD → contact` conversation header, bottom is the input line.
Boards attach on start and stay owned until quit; `/quit` detaches all.

Keys: Tab cycles boards (or completes a partial contact name), F2 opens
the contact picker (Up/Down + Enter, Esc cancels), typing `/` opens the
command palette (Up/Down + Enter), `/to NAME` targets, `/block NAME` +
`/unblock NAME` + `/delete NAME` manage slots, `/radio on|off` (fixed
+2dBm/SF7/BW500 profile, display-only), `/pair offer|proof|confirm`
exports a pairing record, `/find TEXT` searches rooms + history, `/all TEXT`
broadcasts via every board, `/debug` toggles raw-event view, `/status`,
`/contacts`, `/quit`. Plain typing sends to the current target.
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
    "1/2/3 talk as A/B/C · ←/→ switch contact · type + Enter sends · F2 all contacts · /quit leaves",
]

class Tui:
    """Curses state: roster, target, log, input. Bus pumps events in."""
    def __init__(self, stdscr: object, known: dict[str, object]) -> None:
        self.stdscr = stdscr
        self.bus = _bus.EventBus()
        self.known: dict[str, _boards.Board] = dict(known)
        self.order: list[str] = []
        self.current = 0
        self.targets: dict[str, str] = {}
        self.contact_idx: dict[str, int] = {}
        self.log: list[tuple[str, str]] = []
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
        self.rooms: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for serial, board in self.known.items():
            assert isinstance(board, _boards.Board)
            self.bus.attach(board.serial, board.device, board.label)
            self.order.append(serial)
        if not self.order:
            self.status = "no boards attached (check USB)"

    def board(self) -> _boards.Board | None:
        """Current board or None."""
        if not self.order:
            return None
        return self.known.get(self.order[self.current % len(self.order)])

    def names(self, board: _boards.Board) -> list[str]:
        """Mapped names for this board (serial-keyed, arbitrary labels)."""
        return _contacts.names_for(board.serial)

    def target(self, board: _boards.Board) -> str:
        """Current send target name for this board."""
        saved = self.targets.get(board.serial, "")
        if saved and _contacts.valid_name(saved):
            return saved
        names = self.names(board)
        idx = self.contact_idx.get(board.serial, 0) % max(len(names), 1)
        return names[idx] if names else ""

    def complete(self, board: _boards.Board, frag: str) -> list[str]:
        """Mapped names starting with `frag` (case-insensitive)."""
        frag = frag.lower()
        return [n for n in self.names(board) if n.lower().startswith(frag)]

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

    def palette_items(self) -> list[str]:
        """Slash commands for the inline palette."""
        return [
            "/to NAME", "/status", "/contacts", "/settings [KEY]", "/block NAME",
            "/unblock NAME", "/delete NAME", "/radio on", "/radio off",
            "/pair offer", "/pair proof", "/pair confirm", "/debug",
            "/find TEXT", "/all TEXT", "/quit",
        ]

    def room_key(self, serial: str, peer: str) -> tuple[str, str]:
        return (serial, peer)

    def room_msg(self, serial: str, peer: str, text: str, style: str) -> None:
        """Append to the per-contact chatroom and the shared log."""
        self.rooms.setdefault(self.room_key(serial, peer), []).append((style, text[:300]))
        self.rooms[self.room_key(serial, peer)][:] = self.rooms[self.room_key(serial, peer)][-200:]
        self.say(text, style)

    def say(self, text: str, style: str = "paper") -> None:
        """Append one log line, capped."""
        self.log.append((style, text[:300]))
        del self.log[:-500]

    def pump(self) -> None:
        """Drain the bus into the log with contact names resolved."""
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
                self.room_msg(event.board, who, f"[{tag} ← {who}] {event.text}", "moss")
                if board is not None:
                    try:
                        conn = _history.open_history(_local.history_path_for(board.device))
                        try:
                            _history.record_message(conn, contact=who, direction="in",
                                                    epoch=event.epoch, sequence=event.sequence,
                                                    text=event.text)
                        finally:
                            conn.close()
                    except (ValueError, TypeError, OSError, RuntimeError):
                        pass
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
                elif "ACKNOWLEDGED" in event.text:
                    op_id = self._match_op(event.board, obj.get("id"))
                    if op_id is None:
                        op_id = self._oldest_op(event.board)
                    if op_id is not None:
                        s, name, text, _count, _bus = self.pending_sends.pop(op_id)
                        self.room_msg(s, name, f"  ✓ sent · {text}", "dim")
                    elif self.debug:
                        self.say(f"[{tag}] reply: {event.text[:160]}", "dim")
                elif "UNCONFIRMED" in event.text:
                    op_id = self._match_op(event.board, obj.get("id"))
                    if op_id is None:
                        op_id = self._oldest_op(event.board)
                    if op_id is not None:
                        s, name, text, _count, _bus = self.pending_sends.pop(op_id)
                        self.room_msg(s, name, f"  ✗ not sent (no ACK) · {text}", "fault")
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
                        self.room_msg(s, name, f"  … busy, retry {count}/2 · {text}", "dim")
                    else:
                        entry = self.pending_sends.pop(op_id, None)
                        if entry is not None:
                            s, name, text, _count, _bus = entry
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
        """Send the input line to the current target."""
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
            self.say("no target: /to NAME or pair-import first", "fault")
            return
        cid = _contacts.resolve_contact(board.serial, name)
        if cid is None:
            self.say(f"unknown contact '{name}'", "fault")
            return
        bus_id = self._request(board.serial, "send",
                             {"contact_id": cid, "text": text}, timeout=60.0)
        self._send_seq += 1
        self.pending_sends[self._send_seq] = (board.serial, name, text, 0, bus_id)
        self.room_msg(board.serial, name, f"[{board.label or '?'} → {name}] {text}", "amber")
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
            try:
                _history.record_message(conn, contact=name, direction="out",
                                        epoch=0, sequence=0, text=text)
            finally:
                conn.close()
        except (ValueError, TypeError, OSError, RuntimeError):
            pass

    def send_all(self, text: str) -> None:
        """Fan one line out to every board's current target."""
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
                self.say(f"[{board.label or serial[:8]}] no target: /to NAME first", "fault")
                continue
            cid = _contacts.resolve_contact(serial, name)
            if cid is None:
                self.say(f"[{board.label or serial[:8]}] unknown contact '{name}'", "fault")
                continue
            bus_id = self._request(serial, "send",
                                 {"contact_id": cid, "text": text}, timeout=60.0)
            self._send_seq += 1
            self.pending_sends[self._send_seq] = (serial, name, text, 0, bus_id)
            self.room_msg(serial, name, f"[{board.label or '?'} → {name}] {text}", "amber")
            try:
                conn = _history.open_history(_local.history_path_for(board.device))
                try:
                    _history.record_message(conn, contact=name, direction="out",
                                            epoch=0, sequence=0, text=text)
                finally:
                    conn.close()
            except (ValueError, TypeError, OSError, RuntimeError):
                pass

    def find_history(self, needle: str) -> None:
        """Search local histories + live rooms for `needle` (case-insensitive)."""
        needle = needle.strip()
        if not needle:
            self.say("usage: /find TEXT", "fault")
            return
        want = needle.lower()
        hits: list[tuple[str, str]] = []
        for serial in self.order:
            board = self.known.get(serial)
            tag = (board.label if board else serial[:8]) or serial[:8]
            for (_s, peer), msgs in self.rooms.items():
                if _s != serial:
                    continue
                for _style, text in msgs:
                    if want in text.lower():
                        hits.append(("moss", f"[{tag} · {peer}] {text}"))
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
                self.targets[board.serial] = rest.strip()
                self.say(f"target: {rest.strip()}", "amber")
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
        elif cmd == "settings":
            # Read-only display: optional single-key filter. No `settings_set`
            # path here by contract (TUI never writes tunables); use the
            # `meshctl settings KEY VALUE` CLI for writes.
            if board is not None:
                arg = rest.strip()
                params = {"key": arg} if arg else None
                self._request(board.serial, "settings_get", params, timeout=10.0)
        elif cmd == "debug":
            self.debug = not self.debug
            self.say(f"debug {'on' if self.debug else 'off'}", "amber")
        elif cmd == "pair" and rest.strip() in ("offer", "proof", "confirm"):
            if board is not None:
                op = {"offer": "pair_offer", "proof": "pair_proof",
                      "confirm": "pair_confirm"}[rest.strip()]
                self._request(board.serial, op, None, timeout=15.0)
                self.say(f"pair {rest.strip()}: reply lands in log/history", "amber")
        elif cmd == "find":
            self.find_history(rest)
        elif cmd == "all":
            self.send_all(rest)
        else:
            self.say(f"unknown command /{cmd}", "fault")
        return True

    def draw(self) -> None:
        """Paint roster, log, input. Plain curses, no flicker tricks."""
        stdscr = self.stdscr
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        # Roster column (left, 24 wide), per-board version below label.
        for i, serial in enumerate(self.order[: h - 6]):
            board = self.known.get(serial)
            label = (board.label if board else serial[:8]) or serial[:8]
            mark = "●" if i == self.current % len(self.order) else "○"
            line = f"{mark} {label}"[:23]
            try:
                stdscr.addstr(1 + i * 2, 1, line,
                              curses.color_pair(3) if i == self.current % len(self.order)
                              else curses.color_pair(6))
                ver = f"  v{board.firmware_version}"[:23] if board is not None and board.firmware_version else ""
                if ver:
                    stdscr.addstr(2 + i * 2, 1, ver, curses.color_pair(6))
            except curses.error:
                pass
        # Traffic log (center).
        board = self.board()
        target = self.target(board) if board is not None else ""
        header = f"{board.label if board else '—'} → {target or 'no target'} · {self.status}"
        try:
            stdscr.addstr(0, 26, header[: w - 27], curses.color_pair(2))
            stdscr.vline(0, 24, curses.ACS_VLINE, h - 2)
            stdscr.hline(h - 3, 25, curses.ACS_HLINE, w - 26)
        except curses.error:
            pass
        key = self.room_key(board.serial, target) if board is not None and target else None
        room = self.rooms.get(key, []) if key is not None else self.log
        visible = room[-(h - 5):] if key is not None else self.log[-(h - 5):]
        styles = {"amber": 3, "moss": 4, "fault": 5, "paper": 1, "dim": 6}
        for i, (style, text) in enumerate(visible):
            try:
                stdscr.addstr(1 + i, 26, text[: w - 27], curses.color_pair(styles.get(style, 1)))
            except curses.error:
                pass
        # Picker / palette popups above the input line.
        row = h - 4
        if self.picker >= 0 and board is not None:
            for i, name in enumerate(self.names(board)):
                if row - i < 1:
                    break
                try:
                    stdscr.addstr(row - i, 26, f"{'▸' if i == self.picker % max(len(self.names(board)), 1) else ' '} {name}"[: w - 27],
                                  curses.color_pair(3) if i == self.picker % max(len(self.names(board)), 1) else curses.color_pair(6))
                except curses.error:
                    pass
        elif self.palette >= 0:
            items = [c for c in self.palette_items() if self.input[1:].lower() in c.lower()]
            for i, item in enumerate(items[:8]):
                if row - i < 1:
                    break
                try:
                    stdscr.addstr(row - i, 26, f"{'▸' if i == self.palette % max(len(items), 1) else ' '} {item}"[: w - 27],
                                  curses.color_pair(3) if i == self.palette % max(len(items), 1) else curses.color_pair(6))
                except curses.error:
                    pass
        # Input + help.
        try:
            stdscr.addstr(h - 2, 26, ("> " + self.input)[-(w - 27):], curses.color_pair(1))
            stdscr.addstr(h - 1, 1, HELP_LINES[0][: w - 2], curses.color_pair(6))
        except curses.error:
            pass
        try:
            stdscr.move(h - 2, min(28 + len(self.input), w - 1))
        except curses.error:
            pass
        stdscr.refresh()

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
                tui.targets[board.serial] = name
                tui.contact_idx[board.serial] = tui.picker % len(names)
                tui.say(f"target: {name}", "amber")
                tui.picker = -1
            elif key in (curses.KEY_F2, 27):
                tui.picker = -1
            continue
        if key in (curses.KEY_F2,):
            board = tui.board()
            if board is not None and tui.names(board):
                tui.picker = 0
        elif key in (ord("1"), ord("2"), ord("3")) and not tui.input:
            want = "ABC"[key - ord("1")]
            for i, s in enumerate(tui.order):
                if (tui.known[s].label or "?") == want:
                    tui.current = i
                    break
        elif key in (curses.KEY_LEFT, curses.KEY_RIGHT) and not tui.input:
            board = tui.board()
            if board is not None:
                names = tui.names(board)
                if names:
                    step = 1 if key == curses.KEY_RIGHT else -1
                    idx = (tui.contact_idx.get(board.serial, 0) + step) % len(names)
                    tui.contact_idx[board.serial] = idx
                    tui.targets[board.serial] = names[idx]
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
                tui.current = (tui.current + 1) % len(tui.order)
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
