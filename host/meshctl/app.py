"""meshchat: bench console for the three-node Pico LoRa mesh.

Meshtastic-style threads: sidebar conversations (board sections +
contact threads with unread badges) -> thread pane (message bubbles
grouped by contact, backed by history SQLite reads) -> input bar.
Per-message states: queued (◷) / sent (✓) / ACKED (✓✓) / failed (✗).
The header shows board label, epoch/time_valid, radio on/off, and
last counters.

Boards are keyed by USB serial, never ``ttyACM``. Outbound traffic
reads amber, inbound moss, faults red — TX/RX color is radio domain
language. Monospace is the terminal voice of the log.

Run: ``.venv/bin/meshchat`` (same venv as meshctl; stdlib Tk only).
The app owns every attached port while running; ``meshctl chat`` /
``listen`` report PORT_BUSY until the app detaches or exits.
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import boards as _boards
from . import bus as _bus
from . import contacts as _contacts
from . import device as _device
from . import history as _history
from . import local as _local
from . import pairing as _pairing

# Signals-console theme. One accent family per direction; everything
# else sits quiet on the dark bench.
VOID = "#10140F"
PANEL = "#182019"
PANEL_EDGE = "#2A352B"
PAPER = "#E6E1D3"
DIM = "#8A937F"
AMBER = "#E8A33D"  # outbound / actions that transmit
MOSS = "#7DC98F"  # inbound / healthy link
FAULT = "#D95F4B"  # errors / radio off when expected on
MONO = ("DejaVu Sans Mono", 10)
SANS = ("DejaVu Sans", 10)
CALLSIGN = ("DejaVu Sans Mono", 22, "bold")

FIRST_RUN_HELP = (
    "No conversations yet — the 30-second start:\n\n"
    "1. Click Scan, then Attach each station below.\n"
    "2. Click a contact thread on the left (or type a new name\n"
    "   in Send-to + Enter to start a thread).\n"
    "3. Type a message + Enter to send.\n"
    "   ◷ queued · ✓ sent · ✓✓ ACKED · ✗ not delivered\n\n"
    "Pairing a new contact: Offer here, import the QR on the other\n"
    "board, then compare the SAS fingerprints aloud on BOTH sides\n"
    "before confirming. Radio stays on the fixed +2dBm profile."
)

TICKS = {"queued": "◷", "sent": "✓", "acked": "✓✓", "failed": "✗"}


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


class MeshChat(tk.Tk):
    """Root window: thread sidebar, thread pane, rig control."""

    def __init__(self) -> None:
        super().__init__()
        self.title("meshchat — Pico LoRa mesh")
        self.geometry("1220x660")
        self.configure(bg=VOID)
        self.bus = _bus.EventBus()
        self.known: dict[str, _boards.Board] = {}  # serial -> last probe
        self.threads: dict[str, dict[str, Thread]] = {}
        self.info: dict[str, dict] = {}  # serial -> live header facts
        self.current = ""  # selected board serial
        self.sel_thread: str | None = None
        self.attached: set[str] = set()
        self._send_seq = 0
        self._bus_seq: dict[str, int] = {}
        self.pending: dict[int, tuple[str, str, str, int | None]] = {}
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._style()
        self._build()
        self.after(200, self._pump)

    # ---- theme ---------------------------------------------------------
    def _style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=VOID)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=VOID, foreground=PAPER, font=SANS)
        style.configure("Panel.TLabel", background=PANEL, foreground=PAPER)
        style.configure("Dim.TLabel", background=VOID, foreground=DIM, font=SANS)
        style.configure("Active.TLabel", background="#3A4A3C", foreground=PAPER, font=SANS)
        style.configure("Board.TLabel", background=PANEL, foreground=AMBER, font=SANS)
        style.configure("Call.TLabel", background=PANEL, foreground=PAPER, font=CALLSIGN)
        style.configure("TButton", background=PANEL_EDGE, foreground=PAPER,
                        font=SANS, borderwidth=0, padding=(8, 4))
        style.map("TButton", background=[("active", "#3A4A3C")])
        style.configure("Amber.TButton", background="#4A3413", foreground=AMBER)
        style.map("Amber.TButton", background=[("active", "#5C4219")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=PAPER,
                        insertcolor=PAPER)
        style.configure("TCombobox", fieldbackground=PANEL, foreground=PAPER,
                        arrowcolor=PAPER)
        style.configure("TLabelframe", background=VOID, foreground=DIM, font=SANS)
        style.configure("TLabelframe.Label", background=VOID, foreground=DIM)

    # ---- layout ----------------------------------------------------------
    def _build(self) -> None:
        layout = ttk.PanedWindow(self, orient="horizontal")
        layout.pack(fill="both", expand=True)

        left = ttk.Frame(layout, width=250, style="Panel.TFrame")
        layout.add(left, weight=1)
        ttk.Label(left, text="Conversations", style="Panel.TLabel").pack(
            anchor="w", padx=8, pady=(8, 2))
        self.thread_box = ttk.Frame(left, style="Panel.TFrame")
        self.thread_box.pack(fill="both", expand=True, padx=8, pady=2)
        row = ttk.Frame(left, style="Panel.TFrame")
        row.pack(fill="x", padx=8, pady=4)
        ttk.Button(row, text="Scan", command=self._scan).pack(side="left")
        ttk.Button(row, text="Attach", command=self._attach_all).pack(side="left", padx=4)
        ttk.Button(row, text="Detach", command=self._detach_all).pack(side="left")
        ttk.Label(left, text="Send to (new thread)", style="Panel.TLabel").pack(
            anchor="w", padx=8)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Combobox(left, textvariable=self.target_var, width=20)
        self.target_entry.pack(fill="x", padx=8, pady=2)
        self.target_entry.bind("<Return>", lambda _e: self._set_target())
        self.detail = ttk.Label(left, text="Scan, then Attach, then pick a thread",
                                style="Panel.TLabel", wraplength=230,
                                justify="left")
        self.detail.pack(anchor="w", padx=8, pady=(6, 8))

        center = ttk.Frame(layout)
        layout.add(center, weight=4)
        self.center_head = ttk.Label(center, text="Thread — no station selected")
        self.center_head.pack(anchor="w", padx=8, pady=(8, 0))
        self.log = tk.Text(center, wrap="word", state="disabled", height=24,
                           bg=VOID, fg=PAPER, font=MONO, relief="flat",
                           highlightthickness=0, insertbackground=PAPER,
                           selectbackground="#3A4A3C")
        self.log.pack(fill="both", expand=True, padx=8, pady=4)
        self.log.tag_configure("out", foreground=AMBER)
        self.log.tag_configure("in", foreground=MOSS)
        self.log.tag_configure("fault", foreground=FAULT)
        self.log.tag_configure("dim", foreground=DIM)
        entry_row = ttk.Frame(center)
        entry_row.pack(fill="x", padx=8, pady=(0, 8))
        self.entry = ttk.Entry(entry_row)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda _e: self._send())
        ttk.Button(entry_row, text="Send", command=self._send,
                   style="Amber.TButton").pack(side="left", padx=(6, 0))
        self.statusline = ttk.Label(center, text="Idle", style="Dim.TLabel")
        self.statusline.pack(anchor="w", padx=8, pady=(0, 6))

        right = ttk.Frame(layout, width=300)
        layout.add(right, weight=1)
        ttk.Label(right, text="Rig control").pack(anchor="w", padx=8, pady=(8, 0))
        self.debug = tk.Text(right, wrap="word", state="disabled", height=5,
                             bg=VOID, fg=DIM, font=MONO, relief="flat",
                             highlightthickness=0)
        self.debug.pack(fill="x", padx=8, pady=4)
        self._section(right, "Link", (
            ("Status", self._op_status, None),
            ("Contacts", self._op_contacts, None),
            ("Time sync", self._op_time, None),
            ("Radio on", lambda: self._op_radio(True), "Amber.TButton"),
            ("Radio off", lambda: self._op_radio(False), None),
            ("Ping", self._op_ping, None),
            ("Block", self._op_block_unblock(True), None),
            ("Unblock", self._op_block_unblock(False), None),
            ("Delete", self._op_delete, None),
        ))
        self._section(right, "Pairing", (
            ("Offer", lambda: self._pair_export("offer"), None),
            ("Proof", lambda: self._pair_export("proof"), None),
            ("Confirm", lambda: self._pair_export("confirm"), None),
            ("Import", self._pair_import, "Amber.TButton"),
        ))
        self._section(right, "Device", (
            ("Check ELF", self._dev_check, None),
            ("UF2 convert", self._dev_convert, None),
            ("Flash UF2", self._dev_flash, "Amber.TButton"),
            ("Reboot", self._dev_reboot, None),
            ("BOOTSEL", self._dev_bootsel, None),
        ))

    def _section(self, parent: ttk.Frame, title: str,
                 buttons: tuple[tuple[str, object, str | None], ...],
                 columns: int = 3) -> None:
        box = ttk.Labelframe(parent, text=title)
        box.pack(fill="x", padx=8, pady=4)
        inner = ttk.Frame(box)
        inner.pack(fill="x", padx=4, pady=4)
        for index, (label, cmd, style) in enumerate(buttons):
            kwargs = {"style": style} if style else {}
            ttk.Button(inner, text=label, command=cmd, **kwargs).grid(
                row=index // columns, column=index % columns,
                padx=2, pady=2, sticky="ew")
        for column in range(columns):
            inner.columnconfigure(column, weight=1)

    # ---- thread model ------------------------------------------------------
    def _names(self, serial: str) -> list[str]:
        """Mapped contacts first, then live-only peers, stable order."""
        live = list(self.threads.get(serial, {}).keys())
        fresh = [n for n in _contacts.names_for(serial) if n not in self.threads.get(serial, {})]
        for name in fresh:
            self.threads.setdefault(serial, {})[name] = Thread(name)
        return live + fresh

    def _get_thread(self, serial: str, contact: str) -> Thread:
        return self.threads.setdefault(serial, {}).setdefault(contact, Thread(contact))

    def _board(self) -> _boards.Board | None:
        return self.known.get(self.current)

    def _select(self, serial: str, contact: str | None = None) -> None:
        board = self.known.get(serial)
        if board is None:
            return
        self.current = serial
        if contact is not None:
            self.sel_thread = contact
            thread = self.threads.get(serial, {}).get(contact)
            if thread is not None:
                thread.unread = 0
        elif self.sel_thread not in self.threads.get(serial, {}):
            names = self._names(serial)
            self.sel_thread = names[0] if names else None
        self._render_sidebar()
        self._render_thread()
        self._render_header()

    def _render_sidebar(self) -> None:
        for widget in self.thread_box.winfo_children():
            widget.destroy()
        if not self.known:
            ttk.Label(self.thread_box, text=FIRST_RUN_HELP.split("\n")[0],
                      style="Panel.TLabel", wraplength=230,
                      justify="left").pack(anchor="w")
            return
        for serial, board in self.known.items():
            info = self.info.get(serial, {})
            label = info.get("label", board.label) or serial[:8]
            attached = " ●" if serial in self.attached else ""
            ttk.Label(self.thread_box, text=f"{label}{attached}",
                      style="Board.TLabel").pack(anchor="w", pady=(6, 0))
            names = self._names(serial)
            if not names:
                ttk.Label(self.thread_box, text="  (type a name below)",
                          style="Panel.TLabel").pack(anchor="w")
            for name in names:
                thread = self.threads[serial][name]
                badge = f" ({thread.unread})" if thread.unread else ""
                row = ttk.Frame(self.thread_box, style="Panel.TFrame")
                row.pack(fill="x")
                style = "Active.TLabel" if (serial == self.current
                                            and name == self.sel_thread) else "Panel.TLabel"
                lbl = ttk.Label(row, text=f"  {name}{badge}", style=style)
                lbl.pack(side="left", fill="x", expand=True)
                lbl.bind("<Button-1>", lambda _e, s=serial, n=name: self._select(s, n))
                row.bind("<Button-1>", lambda _e, s=serial, n=name: self._select(s, n))

    def _render_header(self) -> None:
        board = self._board()
        if board is None:
            self.center_head.configure(text="Thread — no station selected")
            self.detail.configure(text="Scan, then Attach, then pick a thread")
            return
        info = self.info.get(board.serial, {})
        label = info.get("label", board.label) or "?"
        epoch = info.get("epoch", board.epoch)
        tvalid = info.get("time_valid", board.time_valid)
        radio = info.get("radio_enabled", board.radio_enabled)
        counters = info.get("counters", board.counters) or {}
        tx = counters.get("tx_ok", counters.get("tx", "?"))
        rx = counters.get("rx_ok", counters.get("rx", "?"))
        contact = self.sel_thread or "no thread"
        self.center_head.configure(
            text=f"{label} → {contact} · epoch {epoch} "
                 f"{'⏱ok' if tvalid else '⏱--'} · radio {'ON' if radio else 'OFF'} "
                 f"· tx {tx}/rx {rx}")
        self.detail.configure(
            text=f"{board.device}\n{board.image} rv={board.radio_version} "
                 f"epoch={epoch} contacts={board.contacts.get('count', '?')}")

    def _render_thread(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        thread = None
        if self.current and self.sel_thread:
            thread = self.threads.get(self.current, {}).get(self.sel_thread)
        if thread is None or not thread.msgs:
            if not any(self.threads.get(s) for s in self.threads):
                self.log.insert("end", FIRST_RUN_HELP + "\n", "dim")
            else:
                name = self.sel_thread or "this thread"
                self.log.insert(
                    "end",
                    f"No messages with {name} yet — type below + Enter to send.\n"
                    "◷ queued · ✓ sent · ✓✓ ACKED · ✗ not delivered\n", "dim")
        else:
            for msg in thread.msgs[-200:]:
                if msg.direction == "in":
                    self.log.insert("end", f"← {msg.text}\n", "in")
                else:
                    tick = TICKS.get(msg.state, "?")
                    self.log.insert("end", f"  {msg.text} {tick}\n", "out")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _push(self, serial: str, contact: str, direction: str,
              text: str, state: str) -> None:
        thread = self._get_thread(serial, contact)
        thread.msgs.append(Msg(direction, text[:300], state))
        del thread.msgs[:-200]
        if serial == self.current and contact == self.sel_thread:
            thread.unread = 0
            self._render_thread()
        else:
            thread.unread += 1
            self._render_sidebar()

    def _set_state(self, serial: str, contact: str, text: str,
                   old: tuple[str, ...], new: str) -> None:
        thread = self.threads.get(serial, {}).get(contact)
        if thread is None:
            return
        for msg in reversed(thread.msgs):
            if msg.direction == "out" and msg.text == text and msg.state in old:
                msg.state = new
                break
        if serial == self.current and contact == self.sel_thread:
            self._render_thread()

    # ---- helpers ---------------------------------------------------------

    def _dbg(self, text: str) -> None:
        self.debug.configure(state="normal")
        self.debug.insert("end", text + "\n")
        self.debug.see("end")
        self.debug.configure(state="disabled")

    def _status(self, text: str) -> None:
        self.statusline.configure(text=text)

    def _request(self, serial: str, op: str, params: dict | None,
                 timeout: float) -> int:
        nxt = self._bus_seq.get(serial, 0) + 1
        self._bus_seq[serial] = nxt
        self.bus.request(serial, op, params, timeout=timeout)
        return nxt


    # ---- stations ----------------------------------------------------------
    def _scan(self) -> None:
        found = _boards.probe_all(timeout=5.0)
        self.known = {b.serial: b for b in found}
        for serial, board in self.known.items():
            self.threads.setdefault(serial, {})
            self.info[serial] = {
                "label": board.label, "epoch": board.epoch,
                "time_valid": board.time_valid,
                "radio_enabled": board.radio_enabled,
                "radio_available": board.radio_available,
                "counters": dict(board.counters), "contacts": board.contacts,
            }
            for name in _contacts.names_for(serial):
                self.threads[serial].setdefault(name, Thread(name))
            self._load_history(board)
        if found:
            first = found[0].serial
            names = self._names(first)
            self._select(first, names[0] if names else None)
        else:
            self._dbg("scan: no CDC mesh nodes (check USB cables)")
            self._status("No stations")
            self._render_sidebar()
            self._render_thread()
            self._render_header()
            return
        self._dbg(f"scan: {len(found)} station(s) probed by matched-ID status")
        self._status(f"{len(found)} stations")

    def _load_history(self, board: _boards.Board) -> None:
        """Seed threads from the per-port history SQLite (oldest-first)."""
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
        except (ValueError, TypeError, OSError, RuntimeError):
            return  # DISABLED (--no-history): live traffic only
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
                thread = self._get_thread(board.serial, str(contact))
                thread.msgs.append(Msg(direction, str(text)[:300],
                                       "in" if direction == "in" else "acked"))
                del thread.msgs[:-200]
        finally:
            conn.close()

    def _attach_all(self) -> None:
        board = self._board()
        if board is None:
            self._dbg("attach: Scan first, then select a station")
            return
        self.bus.attach(board.serial, board.device, board.label)
        self.attached.add(board.serial)
        self._status(f"Attached {board.label or board.serial[:8]}")
        self._render_sidebar()
        self._render_header()

    def _attach(self) -> None:
        self._attach_all()

    def _detach(self) -> None:
        if self.current:
            self.bus.detach(self.current)
            self.attached.discard(self.current)
            self._status("Idle")
            self._render_sidebar()
            self._render_header()

    def _detach_all(self) -> None:
        self._detach()


    def _station_row(self, board: _boards.Board) -> None:
        # Legacy probe path: fold a re-probed board into the sidebar.
        self.known[board.serial] = board
        self._render_sidebar()
        self._render_header()

    def _on_select(self, _event: object = None) -> None:
        return None

    def _set_target(self) -> None:
        name = self.target_var.get().strip()
        if not name:
            return
        board = self._board()
        if board is None:
            self._dbg("send-to: Scan + Attach first")
            return
        if not _contacts.valid_name(name):
            self._dbg("send-to: name must be 1-32 non-blank chars")
            return
        self._get_thread(board.serial, name)
        self._select(board.serial, name)
        self.target_var.set("")

    # ---- traffic -------------------------------------------------------------
    def _send(self) -> None:
        text = self.entry.get()
        if not text.strip():
            return
        board = self._board()
        if board is None:
            self._dbg("send: no station selected (Scan + Attach first)")
            return
        name = self.sel_thread or ""
        if not name:
            self._dbg("send: pick a thread on the left first")
            return
        cid = None
        try:
            cid = _contacts.resolve_contact(board.serial, name)
        except (ValueError, OSError, RuntimeError):
            cid = None
        params: dict = {"text": text}
        if cid is not None:
            params["contact_id"] = cid
        else:
            self._dbg(f"send: unknown contact '{name}' (pair import first)")
            return
        if len(text.encode("utf-8")) > 160 or not text:
            self._dbg("send: text must be 1-160 UTF-8 bytes, never truncated")
            return
        bus_id = self._request(board.serial, "send", params, timeout=60.0)
        self._send_seq += 1
        self.pending[self._send_seq] = (board.serial, name, text, bus_id)
        self._push(board.serial, name, "out", text, "sent")
        self._status(f"Sending to {name}…")
        self._remember(board, name, "out", text)
        self.entry.delete(0, "end")

    def _remember(self, board: _boards.Board, contact: str, direction: str, text: str) -> None:
        try:
            conn = _history.open_history(_local.history_path_for(board.device))
            try:
                _history.record_message(conn, contact=contact, direction=direction,
                                        epoch=0, sequence=0, text=text)
            finally:
                conn.close()
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            self._dbg(f"history write failed: {exc}")

    def _pump(self) -> None:
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
                self._push(event.board, who, "in", event.text, "in")
                if board is not None:
                    self._remember(board, who, "in", event.text)
            elif event.kind == "reply":
                try:
                    obj = json.loads(event.text)
                except ValueError:
                    self._dbg(f"[{tag}] malformed reply")
                    continue
                result = obj.get("result", {}) if isinstance(obj, dict) else {}
                status = result.get("status", "") if isinstance(result, dict) else ""
                if isinstance(result, dict) and ("epoch" in result or "counters" in result
                                                 or "label" in result):
                    info = self.info.setdefault(event.board, {})
                    for key in ("label", "epoch", "time_valid", "radio_enabled",
                                "radio_available", "counters", "contacts"):
                        if key in result:
                            info[key] = result[key]
                    self._render_sidebar()
                    self._render_header()
                    if not status:
                        continue
                if status == "ACKNOWLEDGED":
                    op_id = self._match(event.board, obj.get("id"))
                    if op_id is not None:
                        s, name, text, _bus = self.pending.pop(op_id)
                        self._set_state(s, name, text, ("sent", "queued"), "acked")
                    self._status(f"{tag} acknowledged ✓✓")
                elif status == "UNCONFIRMED":
                    op_id = self._match(event.board, obj.get("id"))
                    if op_id is not None:
                        s, name, text, _bus = self.pending.pop(op_id)
                        self._set_state(s, name, text, ("sent", "queued"), "failed")
                    self._status(f"{tag}: not delivered ✗")
                    self._dbg(f"[{tag}] UNCONFIRMED (peer off, radio off, or out of range)")
                elif status:
                    self._status(f"{tag}: {status}")
                    self._dbg(f"[{tag}] {status}")
                else:
                    self._dbg(f"[{tag}] reply: {event.text[:200]}")
            else:
                self._dbg(f"[{tag}] {event.text[:200]}")
        self.after(200, self._pump)

    def _match(self, serial: str, reply_id: object) -> int | None:
        """Oldest pending send op for `serial` with the reply id."""
        if type(reply_id) is int:
            for op_id in sorted(self.pending):
                s, _n, _t, bus_id = self.pending[op_id]
                if s == serial and bus_id == reply_id:
                    return op_id
        for op_id in sorted(self.pending):
            if self.pending[op_id][0] == serial:
                return op_id
        return None

    # ---- link ---------------------------------------------------------------
    def _op_status(self) -> None:
        board = self._board()
        if board:
            self.bus.request(board.serial, "status", None, timeout=5.0)

    def _op_contacts(self) -> None:
        board = self._board()
        if board:
            self.bus.request(board.serial, "contacts", None, timeout=5.0)

    def _op_time(self) -> None:
        import time as _time

        board = self._board()
        if board:
            self.bus.request(board.serial, "time_set",
                             {"unix_seconds": int(_time.time())}, timeout=5.0)

    def _op_radio(self, enabled: bool) -> None:
        board = self._board()
        if board:
            if enabled and not messagebox.askyesno(
                    "Radio on", f"Enable RF on {board.label or board.serial[:8]}?"):
                return
            self.bus.request(board.serial, "radio_set", {"enabled": enabled}, timeout=10.0)

    def _op_ping(self) -> None:
        board = self._board()
        if board:
            self.bus.request(board.serial, "ping", {"count": 1}, timeout=30.0)

    def _op_block_unblock(self, blocked: bool):
        def run() -> None:
            board = self._board()
            if board is None:
                return
            name = (self.sel_thread or "").strip()
            cid = None
            try:
                cid = _contacts.resolve_contact(board.serial, name) if name else None
            except (ValueError, OSError, RuntimeError):
                cid = None
            if cid is None:
                self._dbg(f"{'block' if blocked else 'unblock'}: unknown contact '{name}'")
                return
            self.bus.request(board.serial, "block" if blocked else "unblock",
                             {"contact_id": cid}, timeout=10.0)
        return run

    def _op_delete(self) -> None:
        board = self._board()
        if board is None:
            return
        name = (self.sel_thread or "").strip()
        try:
            cid = _contacts.resolve_contact(board.serial, name) if name else None
        except (ValueError, OSError, RuntimeError):
            cid = None
        if cid is None:
            self._dbg(f"delete: unknown contact '{name}'")
            return
        if not messagebox.askyesno("Delete contact", f"Delete '{name}' (id {cid})? Frees the slot."):
            return
        self.bus.request(board.serial, "contact_delete", {"contact_id": cid}, timeout=10.0)

    # ---- pairing --------------------------------------------------------------
    def _pair_export(self, kind: str) -> None:
        board = self._board()
        if board is None:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png", initialfile=f"{kind}-{board.label or 'node'}.png")
        if not path:
            return
        self._pair_export_to(kind, board, path)

    def _pair_export_to(self, kind: str, board: _boards.Board, path: str) -> None:
        from . import serial_link as _sl

        op = {"offer": "pair_offer", "proof": "pair_proof", "confirm": "pair_confirm"}[kind]
        try:
            with _sl.SerialSession(board.device) as session:
                reply, _ = session.exchange(op, None, 10.0)
        except (_sl.PortBusyError, _sl.TimeoutError, ValueError, RuntimeError, OSError) as exc:
            self._dbg(f"pair {kind}: {exc} (detach the station first)")
            return
        record = (reply.get("result", {}) or {}).get("record_b64", "")
        if not reply.get("ok") or not record:
            self._dbg(f"pair {kind}: {reply.get('error', 'no record')}")
            return
        transport = record if record.startswith(_pairing.PREFIX) else _pairing.PREFIX + record
        try:
            _pairing.write_png(transport, path)
        except (RuntimeError, OSError, ValueError, ImportError) as exc:
            self._dbg(f"pair {kind}: QR write failed: {exc}")
            return
        self._dbg(f"pair {kind}: wrote {path} (compare fingerprints aloud)")

    def _pair_import(self) -> None:
        import tkinter.simpledialog as _sd

        board = self._board()
        if board is None:
            return
        path = filedialog.askopenfilename(filetypes=[("QR PNG", "*.png")])
        if not path:
            return
        name = _sd.askstring("Contact name", "Local display name:")
        if not name:
            return
        sas = _sd.askstring("SAS check",
            "Compare the transcript aloud on BOTH sides, then type YES to activate confirmation records:")
        sas_match = bool(sas) and sas.strip().upper() == "YES"
        from . import serial_link as _sl

        try:
            text = _pairing.read_text_from_image(path)
        except (OSError, ValueError, ImportError) as exc:
            self._dbg(f"pair import: QR read failed: {exc}")
            return
        try:
            with _sl.SerialSession(board.device) as session:
                params = {"record_b64": text}
                if sas_match:
                    params["sas_match"] = True
                reply, _ = session.exchange(
                    "pair_import", params, 10.0)
        except (_sl.PortBusyError, _sl.TimeoutError, ValueError, RuntimeError, OSError) as exc:
            self._dbg(f"pair import: {exc} (detach the station first)")
            return
        if not reply.get("ok"):
            self._dbg(f"pair import: {reply.get('error', 'UNKNOWN')}")
            return
        contact_id = (reply.get("result", {}) or {}).get("contact_id")
        fingerprint = (reply.get("result", {}) or {}).get("fingerprint", "")
        self._dbg(f"pair import: fingerprint={fingerprint} contact_id={contact_id}")
        if isinstance(contact_id, int) and 1 <= contact_id <= 2:
            try:
                _contacts.set_contact(board.serial, name, contact_id)
            except (ValueError, OSError, RuntimeError) as exc:
                self._dbg(f"mapping write failed: {exc}")

    # ---- device (sudo-free) ------------------------------------------------------
    def _dev_check(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("ELF", "*.elf")])
        if not path:
            return
        try:
            result = _device.check_elf(path)
        except (OSError, ValueError) as exc:
            self._dbg(f"ELF check FAIL: {exc}")
            return
        self._dbg(f"ELF PASS: entry=0x{result['entry']:08x} "
                  f"stored={result['stored_bytes']}B segs={result['load_segments']}")

    def _dev_convert(self) -> None:
        src = filedialog.askopenfilename(filetypes=[("ELF", "*.elf")])
        if not src:
            return
        dst = filedialog.asksaveasfilename(defaultextension=".uf2",
                                           initialfile=src.rsplit("/", 1)[-1].replace(".elf", ".uf2"))
        if not dst:
            return
        try:
            _device.uf2_convert(src, dst)
        except RuntimeError as exc:
            self._dbg(f"uf2 convert: {exc}")
            return
        self._dbg(f"uf2 convert: wrote {dst}")

    def _dev_flash(self) -> None:
        uf2 = filedialog.askopenfilename(filetypes=[("UF2", "*.uf2")])
        if not uf2:
            return
        volumes = _boards.bootsel_volumes()
        if len(volumes) != 1:
            self._dbg(f"flash: need exactly 1 BOOTSEL volume, saw {len(volumes)} "
                      "(put one station in BOOTSEL)")
            return
        try:
            mount = _device.mount_bootsel(volumes[0].dev)
            result = _device.flash_uf2(uf2, mount)
        except (ValueError, RuntimeError) as exc:
            self._dbg(f"flash: {exc}")
            return
        self._dbg(f"flash: {result.bytes_copied}B -> {result.volume} "
                  f"rebooted={result.rebooted_to_app} (re-scan after boot)")

    def _dev_reboot(self) -> None:
        try:
            out = _device.live_command("reboot")
        except RuntimeError as exc:
            self._dbg(f"reboot: {exc}")
            return
        self._dbg(f"reboot: {out.strip()[:120]}")

    def _dev_bootsel(self) -> None:
        if not messagebox.askyesno("BOOTSEL", "Reboot station into BOOTSEL storage?"):
            return
        try:
            out = _device.live_command("reboot", "-u")
        except RuntimeError as exc:
            self._dbg(f"reboot -u: {exc}")
            return
        self._dbg(f"reboot -u: {out.strip()[:120]}")

    def _on_close(self) -> None:
        self.bus.detach_all()
        self.destroy()


def main() -> None:
    """``meshchat`` entry point (no args; everything is buttons)."""
    import os as _os
    _history.DISABLED = _os.environ.get("MESHCTL_NO_HISTORY", "").strip().lower() in ("1", "true", "yes")
    app = MeshChat()
    app.mainloop()


if __name__ == "__main__":
    main()
