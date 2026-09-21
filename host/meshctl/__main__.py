"""USB terminal interface: 1:1 mapping onto firmware ops.

No key agreement or message encryption in Python: pairing records are
opaque ``LMESH1:`` text moved between firmware and QR PNG files, and all
key material stays in firmware. Contact names are local operator labels
(``.mesh-local/host-contacts.json``); firmware slots stay authoritative.

Exit statuses: 0 success (``ACKNOWLEDGED`` / command ok); 1 local error,
firmware ``ok:false``, timeout, ``PORT_BUSY``, invalid QR, or
``UNCONFIRMED`` (bounded retries exhausted); 2 CLI usage errors
(argparse default).
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time

from . import cli_extra, contacts, history, local as _local, pairing, serial_link

MAX_TEXT_BYTES = 160
RADIO_UNAVAILABLE_HINT = (
    "radio-free image: no RF hardware on this build;"
    " pairing/contact/time logic is still exercisable, RF is not"
)


def _err(msg: str) -> int:
    print(f"meshctl: error: {msg}", file=sys.stderr)
    return 1


def _firmware_error(error: str) -> int:
    if error == "RADIO_UNAVAILABLE":
        return _err(f"firmware error: RADIO_UNAVAILABLE ({RADIO_UNAVAILABLE_HINT})")
    if error == "RADIO_MUST_BE_OFF":
        return _err("firmware error: RADIO_MUST_BE_OFF (run `radio off` first; pairing never transmits)")
    return _err(f"firmware error: {error}")

def _do_exchange(args: argparse.Namespace, op: str, params: dict | None) -> dict | int:
    """One owned exchange; returns the reply dict or an exit code."""
    from .transports import open_session
    label = args.port if getattr(args, "transport", "usb") == "usb" else f"{args.tcp_host}:{args.tcp_port}"
    try:
        with open_session(
            getattr(args, "transport", "usb"),
            device=args.port or "",
            host=getattr(args, "tcp_host", "127.0.0.1"),
            tcp_port=getattr(args, "tcp_port", 7777),
        ) as session:
            reply, events = session.exchange(op, params, args.timeout)
    except serial_link.PortBusyError:
        return _err(f"PORT_BUSY: {label} is owned by another process (one owner per port)")

def _note_received(port: str, evt: dict) -> None:
    """Show an interleaved ``received`` event and keep it in history."""
    contact_id = evt.get("contact_id")
    serial = contacts.serial_for_port(port)
    label = contacts.name_for_id(serial, contact_id) if isinstance(contact_id, int) else None
    if label is None:
        label = f"id{contact_id}" if isinstance(contact_id, int) else str(contact_id)
    print(json.dumps(evt, ensure_ascii=False), file=sys.stderr)
    try:
        conn = history.open_history(_local.history_path_for(port))
        try:
            history.record_message(
                conn,
                contact=label,
                direction="in",
                epoch=int(evt.get("epoch", 0)),
                sequence=int(evt.get("sequence", 0)),
                text=str(evt.get("text", "")),
            )
        finally:
            conn.close()
    except (ValueError, TypeError, OSError) as exc:
        print(f"meshctl: warning: history write failed: {exc}", file=sys.stderr)


def _print_result(reply: dict) -> None:
    print(json.dumps(reply.get("result", {}), indent=2, ensure_ascii=False))


# ---- target resolution -----------------------------------------------------

def _resolve_send_target(port: str, name: str) -> tuple[dict | None, str]:
    """``(params, describe)`` for ``send``; arbitrary names via mapping."""
    serial = contacts.serial_for_port(port)
    cid = contacts.resolve_contact(serial, name)
    if cid is not None:
        return {"contact_id": cid}, f"contact {name} (id {cid})"
    return None, f"unknown contact '{name}' (pair import first with --name '{name}')"


def _resolve_block_target(port: str, name: str) -> tuple[int | None, str]:
    """Blocking needs a real paired slot: mapping only, no lab fallback."""
    cid = contacts.resolve_contact(contacts.serial_for_port(port), name)
    if cid is not None:
        return cid, f"contact {name} (id {cid})"
    return None, f"unknown contact '{name}' (blocking needs a paired contact: pair import first)"


# ---- simple commands --------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    reply = _do_exchange(args, "status", None)
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_settings(args: argparse.Namespace) -> int:
    """Read-only-safe settings CLI: `settings` lists all entries, `settings KEY`
    narrows to one, `settings KEY VALUE` clamps + stores (firmware clamps;
    unknown/readonly keys are BAD_REQUEST). TX power applies at next radio-on."""
    params: dict | None = None
    if args.key is not None and args.value is None:
        params = {"key": args.key}
        op = "settings_get"
    elif args.key is not None:
        params = {"key": args.key, "value": args.value}
        op = "settings_set"
    else:
        op = "settings_get"
    reply = _do_exchange(args, op, params)
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_wifi(args: argparse.Namespace) -> int:
    """WiFi credential CLI: `wifi status` reports configured/ssid_len (never
    secrets); `wifi set --ssid S [--pass P]` validates + durably commits
    (firmware joins live, no reboot); `wifi forget` clears the stored
    credential. Passphrase never appears in output or logs."""
    if args.wifi_cmd == "status":
        reply = _do_exchange(args, "wifi_status", None)
    elif args.wifi_cmd == "set":
        if not args.ssid:
            return _err("wifi set needs --ssid SSID (1-32 chars)")
        reply = _do_exchange(args, "wifi_set", {"ssid": args.ssid, "pass": getattr(args, "passwd", "") or ""})
    elif args.wifi_cmd == "forget":
        reply = _do_exchange(args, "wifi_forget", None)
    else:
        return _err(f"unknown wifi subcommand {args.wifi_cmd!r}")
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_ports(args: argparse.Namespace) -> int:
    del args
    for entry in serial_link.list_ports_detailed():
        vidpid = f"{entry['vid']}:{entry['pid']}" if entry["vid"] else "-"
        serial = entry["serial"] or "-"
        print(f"{entry['device']}\tVID:PID={vidpid}\tserial={serial}\t{entry['description']}".rstrip())


def cmd_provision(args: argparse.Namespace) -> int:
    if args.label not in ("A", "B", "C"):
        return _err("label must be A, B or C")
    reply = _do_exchange(args, "provision", {"label": args.label})
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def _parse_utc(value: str) -> int | None:
    if value == "now":
        return int(time.time())
    try:
        return int(value)
    except ValueError:
        pass
    try:
        from datetime import datetime, timezone

        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def cmd_time(args: argparse.Namespace) -> int:
    if args.time_cmd == "status":
        reply = _do_exchange(args, "time_status", None)
        if isinstance(reply, int):
            return reply
        _print_result(reply)
        return 0
    secs = _parse_utc(args.utc)
    if secs is None or secs < 0:
        return _err("--utc must be 'now', unix seconds, or ISO-8601")
    reply = _do_exchange(args, "time_set", {"unix_seconds": secs})
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_radio(args: argparse.Namespace) -> int:
    if args.radio_cmd == "on":
        reply = _do_exchange(args, "radio_set", {"enabled": True})
    elif args.radio_cmd == "off":
        reply = _do_exchange(args, "radio_set", {"enabled": False})
    else:
        reply = _do_exchange(args, "radio_arm_next_boot", None)
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    if args.count < 1 or args.count > 3:
        return _err("--count must be 1-3 (bounded lab probe)")
    reply = _do_exchange(args, "ping", {"count": args.count})
    if isinstance(reply, int):
        return reply
    _print_result(reply)
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    text_bytes = args.text.encode("utf-8")
    if not (1 <= len(text_bytes) <= MAX_TEXT_BYTES):
        return _err(f"text must be 1-{MAX_TEXT_BYTES} UTF-8 bytes (got {len(text_bytes)}); oversize is rejected, never truncated")
    params, describe = _resolve_send_target(args.port, args.contact)
    if params is None:
        return _err(describe)
    params = dict(params)
    params["text"] = args.text
    try:
        from .transports import open_session
        with open_session(
            getattr(args, "transport", "usb"),
            device=args.port or "",
            host=getattr(args, "tcp_host", "127.0.0.1"),
            tcp_port=getattr(args, "tcp_port", 7777),
        ) as session:
            reply, events = session.exchange("send", params, args.timeout)
    except serial_link.PortBusyError:
        label = args.port if getattr(args, "transport", "usb") == "usb" else f"{args.tcp_host}:{args.tcp_port}"
        return _err(f"PORT_BUSY: {label} is owned by another process (one owner per port)")
    except serial_link.TimeoutError as exc:
        return _err(f"timeout waiting for send outcome (bounded retries may still be on air): {exc}")
    except (ValueError, RuntimeError, OSError) as exc:
        return _err(str(exc))
    for evt in events:
        if isinstance(evt, dict) and evt.get("event") == "received":
            _note_received(args.port, evt)
    if not reply.get("ok"):
        return _firmware_error(str(reply.get("error", "UNKNOWN")))
    status = reply.get("result", {}).get("status", "")
    try:
        conn = history.open_history(_local.history_path_for(args.port))
        try:
            history.record_message(conn, contact=args.contact, direction="out", epoch=0, sequence=0, text=args.text)
        finally:
            conn.close()
    except (ValueError, TypeError, OSError) as exc:
        print(f"meshctl: warning: history write failed: {exc}", file=sys.stderr)
    if status == "ACKNOWLEDGED":
        print("ACKNOWLEDGED")
        return 0
    if status == "UNCONFIRMED":
        return _err(f"UNCONFIRMED to {describe}: bounded retries exhausted (peer off, route down, relay missing)")
    return _err(f"unexpected send status: {status!r}")


def cmd_contacts(args: argparse.Namespace) -> int:
    reply = _do_exchange(args, "contacts", None)
    if isinstance(reply, int):
        return reply
    result = reply.get("result", {})
    rows = result.get("contacts", [])
    mappings = contacts.load_mappings().get(contacts.serial_for_port(args.port), {})
    reverse = {cid: name for name, cid in mappings.items() if isinstance(cid, int)}
    for row in rows:
        cid = row.get("contact_id")
        name = reverse.get(cid, "")
        fingerprint = row.get("fingerprint", "")
        print(f"id={cid} present={row.get('present')} blocked={row.get('blocked')} name={name} fingerprint={fingerprint}".rstrip())
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    serial = contacts.serial_for_port(args.port)
    cid, describe = _resolve_block_target(args.port, args.contact)
    if cid is None:
        return _err(describe)
    reply = _do_exchange(args, "contact_delete", {"contact_id": cid})
    if isinstance(reply, int):
        return reply
    contacts.drop_contact(serial, args.contact, cid)
    print(f"deleted {describe} (slot freed locally and on board)")
    return 0


def cmd_block(args: argparse.Namespace, blocked: bool) -> int:
    cid, describe = _resolve_block_target(args.port, args.contact)
    if cid is None:
        return _err(describe)
    op = "block" if blocked else "unblock"
    reply = _do_exchange(args, op, {"contact_id": cid})
    if isinstance(reply, int):
        return reply
    print(f"{op}ed {describe}")
    return 0


# ---- pairing ----------------------------------------------------------------

_PAIR_OPS = {"offer": "pair_offer", "proof": "pair_proof", "confirm": "pair_confirm"}
_PAIR_KINDS = {"offer": "offer", "proof": "proof", "confirm": "confirmation"}


def cmd_pair_export(args: argparse.Namespace) -> int:
    op = _PAIR_OPS[args.pair_cmd]
    reply = _do_exchange(args, op, None)
    if isinstance(reply, int):
        return reply
    record_b64 = reply.get("result", {}).get("record_b64", "")
    if not isinstance(record_b64, str) or not record_b64:
        return _err("firmware returned no record_b64")
    transport = record_b64 if record_b64.startswith(pairing.PREFIX) else pairing.PREFIX + record_b64
    try:
        raw, kind = pairing.decode_record_kind(transport)
    except ValueError as exc:
        return _err(f"firmware record failed strict validation ({exc}); nothing written")
    if kind != _PAIR_KINDS[args.pair_cmd]:
        return _err(f"firmware returned a {kind} record for a {args.pair_cmd} export; nothing written")
    try:
        pairing.write_png(transport, args.out)
    except RuntimeError as exc:
        return _err(str(exc))
    except (OSError, ValueError, ImportError) as exc:
        return _err(f"QR PNG write failed: {exc}")
    try:
        _local.write_private_bytes(
            _local.records_dir() / f"{args.pair_cmd}-{int(time.time())}.txt",
            (transport + "\n").encode("utf-8"),
        )
    except OSError as exc:
        print(f"meshctl: warning: audit copy failed: {exc}", file=sys.stderr)
    fingerprint = reply.get("result", {}).get("fingerprint") or pairing.fingerprint_of_record_b64(transport) or pairing.fingerprint_of_offer(transport)
    if kind == "offer":
        print(f"offer written to {args.out}; signing-key id={fingerprint or '-'}; peer imports this, then compare proof fingerprints aloud")
    else:
        print(f"{kind} written to {args.out}; transcript={fingerprint or '-'} (compare aloud on both sides; mismatch aborts)")
    _ = raw
    return 0


def cmd_pair_import(args: argparse.Namespace) -> int:
    if not contacts.valid_name(args.name):
        return _err("--name must be 1-32 non-blank chars (any operator label)")
    try:
        text = pairing.read_text_from_image(args.file)
    except (OSError, ValueError, ImportError) as exc:
        return _err(f"QR import failed (no contact mutation): {exc}")
    try:
        _raw, kind = pairing.decode_record_kind(text)
    except ValueError as exc:
        # Strict gate: an invalid record never reaches firmware or mappings.
        return _err(f"invalid pairing record (no contact mutation): {exc}")
    # Firmware `decode_transport` requires the full `LMESH1:` transport text;
    # the bare base64 body alone is BAD_REQUEST.
    params: dict = {"record_b64": text, "replace": bool(args.replace)}
    if args.lab_address is not None:
        # Firmware has no `lab_address` field on `pair_import` in this secure
        # image; reject it here instead of transmitting an ignored value.
        return _err("--lab-address is not supported by this firmware image (no contact mutation)")
    reply = _do_exchange(args, "pair_import", params)
    if isinstance(reply, int):
        return reply
    result = reply.get("result", {})
    progress = result.get("progress", result.get("stage", result.get("status", "")))
    fingerprint = result.get("fingerprint", result.get("transcript", result.get("transcript_fingerprint", "")))
    contact_id = result.get("contact_id")
    print(f"imported {kind}: progress={progress} fingerprint={fingerprint}".rstrip())
    if isinstance(contact_id, bool) or not isinstance(contact_id, int):
        print("no activation yet (further records needed); mappings unchanged")
        return 0
    if contact_id < 1 or contact_id > contacts.MAX_CONTACTS:
        return _err(f"firmware reported invalid contact_id {contact_id!r}; mappings unchanged")
    try:
        contacts.set_contact(contacts.serial_for_port(args.port), args.name, contact_id)
    except (ValueError, OSError) as exc:
        return _err(f"activation ok but mapping write failed (trust lives in firmware): {exc}")
    print(f"contact '{args.name}' activated as id {contact_id} (mapping saved locally)")
    return 0


# ---- receive loops -----------------------------------------------------------

def _display_line(port: str, obj: dict) -> None:
    if not isinstance(obj, dict):
        return
    if obj.get("event") == "received":
        _note_received(port, obj)
    elif "event" in obj:
        print(json.dumps(obj, ensure_ascii=False))
    elif "_noise" in obj:
        print(f"meshctl: note: {obj['_noise']}", file=sys.stderr)
    elif "ok" in obj:
        # Late/stray reply to no outstanding request: log, never drop.
        print(f"meshctl: late reply: {json.dumps(obj, ensure_ascii=False)}", file=sys.stderr)


def cmd_listen(args: argparse.Namespace) -> int:
    from .transports import open_session
    label = args.port if getattr(args, "transport", "usb") == "usb" else f"{args.tcp_host}:{args.tcp_port}"
    try:
        session = open_session(
            getattr(args, "transport", "usb"),
            device=args.port or "",
            host=getattr(args, "tcp_host", "127.0.0.1"),
            tcp_port=getattr(args, "tcp_port", 7777),
        ).open()
    except serial_link.PortBusyError:
        return _err(f"PORT_BUSY: {label} is owned by another process (one owner per port)")
    except (RuntimeError, OSError) as exc:
        return _err(str(exc))
    deadline = time.monotonic() + args.seconds if args.seconds else None
    print(f"listening on {args.port} (Ctrl-C to stop)...", file=sys.stderr)
    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                obj = session.read_next(timeout=1.0)
            except serial_link.TimeoutError as exc:
                print(f"meshctl: note: {exc}", file=sys.stderr)
                continue
            if obj is not None:
                _display_line(args.port, obj)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
    return 0


CHAT_HELP = (
    "/to NAME      send target (paired name, or A/B/C in lab)\n"
    "/block NAME   block a paired contact\n"
    "/unblock NAME unblock a paired contact\n"
    "/status       firmware status\n"
    "/radio off    disable radio (cancels pending work)\n"
    "/quit         leave chat\n"
    "any other line sends text to the current target"
)


def cmd_chat(args: argparse.Namespace) -> int:
    from .transports import open_session
    label = args.port if getattr(args, "transport", "usb") == "usb" else f"{args.tcp_host}:{args.tcp_port}"
    try:
        session = open_session(
            getattr(args, "transport", "usb"),
            device=args.port or "",
            host=getattr(args, "tcp_host", "127.0.0.1"),
            tcp_port=getattr(args, "tcp_port", 7777),
        ).open()
    except serial_link.PortBusyError:
        return _err(f"PORT_BUSY: {label} is owned by another process (one owner per port)")
    ser_lock = threading.Lock()
    paused = threading.Event()
    stop = threading.Event()
    target: dict | None = None
    target_name = ""

    if args.contact:
        params, describe = _resolve_send_target(args.port, args.contact)
        if params is None:
            session.close()
            return _err(describe)
        target, target_name = params, args.contact

    def reader() -> None:
        while not stop.is_set():
            if paused.is_set():
                time.sleep(0.05)
                continue
            with ser_lock:
                if paused.is_set():
                    continue
                try:
                    obj = session.read_next(timeout=1.0)
                except serial_link.TimeoutError as exc:
                    print(f"meshctl: note: {exc}", file=sys.stderr)
                    continue
                except OSError as exc:
                    print(f"meshctl: serial error: {exc}", file=sys.stderr)
                    stop.set()
                    return
            if obj is not None:
                _display_line(args.port, obj)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    print(f"chat on {args.port}; type /help for commands.", file=sys.stderr)

    def chat_exchange(op: str, params: dict, timeout: float) -> dict | None:
        paused.set()
        try:
            with ser_lock:
                reply, events = session.exchange(op, params, timeout)
        except (serial_link.TimeoutError, ValueError, RuntimeError, OSError) as exc:
            print(f"meshctl: error: {exc}", file=sys.stderr)
            return None
        finally:
            paused.clear()
        for evt in events:
            if isinstance(evt, dict):
                _display_line(args.port, evt)
        if not reply.get("ok"):
            _firmware_error(str(reply.get("error", "UNKNOWN")))
            return None
        return reply

    rc = 0
    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            if not line.strip():
                continue
            if line.startswith("/"):
                cmd, _, rest = line[1:].partition(" ")
                word, _, name = rest.partition(" ")
                name = (name or word).strip() if cmd in ("to", "block", "unblock") else rest.strip()
                if cmd == "quit":
                    break
                elif cmd in ("help", "?"):
                    print(CHAT_HELP)
                elif cmd == "to":
                    params, describe = _resolve_send_target(args.port, name) if name else (None, "usage: /to NAME")
                    if params is None:
                        print(f"meshctl: error: {describe}", file=sys.stderr)
                    else:
                        target, target_name = params, name
                        print(f"target: {describe}")
                elif cmd in ("block", "unblock"):
                    cid, describe = _resolve_block_target(args.port, name) if name else (None, f"usage: /{cmd} NAME")
                    if cid is None:
                        print(f"meshctl: error: {describe}", file=sys.stderr)
                    elif chat_exchange(cmd, {"contact_id": cid}, 10.0) is not None:
                        print(f"{cmd}ed {describe}")
                elif cmd == "status":
                    reply = chat_exchange("status", {}, 5.0)
                    if reply is not None:
                        print(json.dumps(reply.get("result", {}), indent=2, ensure_ascii=False))
                elif cmd == "radio" and rest.strip() == "off":
                    if chat_exchange("radio_set", {"enabled": False}, 5.0) is not None:
                        print("radio off")
                else:
                    print(f"meshctl: unknown command {line!r}; /help lists commands", file=sys.stderr)
                continue
            if target is None:
                print("meshctl: no target; set one with /to NAME first", file=sys.stderr)
                continue
            if len(line.encode("utf-8")) > MAX_TEXT_BYTES:
                print(f"meshctl: error: text over {MAX_TEXT_BYTES} bytes; rejected, never truncated", file=sys.stderr)
                continue
            params = dict(target)
            params["text"] = line
            reply = chat_exchange("send", params, serial_link.SEND_TIMEOUT)
            if reply is None:
                continue
            status = reply.get("result", {}).get("status", "")
            print(status)
            try:
                conn = history.open_history(_local.history_path_for(args.port))
                try:
                    history.record_message(conn, contact=target_name, direction="out", epoch=0, sequence=0, text=line)
                finally:
                    conn.close()
            except (ValueError, TypeError, OSError) as exc:
                print(f"meshctl: warning: history write failed: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return rc


# ---- parser -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="meshctl", description="USB terminal for three-node Pico LoRa mesh (host holds no keys)")
    parser.add_argument("--port", default=None, help="serial path (required for --transport usb, except for ports)")
    parser.add_argument("--transport", default="usb", choices=["usb", "tcp"], help="usb CDC (default) or TCP over WiFi (firmware TCP server, port 7777)")
    parser.add_argument("--tcp-host", default="127.0.0.1", help="WiFi target host (only with --transport tcp)")
    parser.add_argument("--tcp-port", type=int, default=7777, help="WiFi target port (default 7777, mirrors firmware wifi.rs TCP_PORT)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="firmware status")
    sub.add_parser("ports", help="list serial ports (needs no --port)")

    p_provision = sub.add_parser("provision", help="provision board label")
    p_provision.add_argument("--label", required=True, choices=["A", "B", "C"])

    p_time = sub.add_parser("time", help="clock handling")
    t_sub = p_time.add_subparsers(dest="time_cmd", required=True)
    p_set = t_sub.add_parser("set", help="set clock from host UTC")
    p_set.add_argument("--utc", default="now", help="'now', unix seconds, or ISO-8601 (default now)")
    t_sub.add_parser("status", help="clock status")

    p_radio = sub.add_parser("radio", help="radio control")
    r_sub = p_radio.add_subparsers(dest="radio_cmd", required=True)
    r_sub.add_parser("on", help="enable radio")
    r_sub.add_parser("off", help="disable radio (cancels pending work)")
    r_sub.add_parser("arm-next-boot", help="one-shot relay arming for next boot")

    p_ping = sub.add_parser("ping", help="liveness probe (count 1-3)")
    p_ping.add_argument("--ping-timeout", dest="timeout", type=float, default=30.0, help="reply deadline in seconds")

    p_send = sub.add_parser("send", help="send a text message")
    p_send.add_argument("--contact", required=True, help="paired contact name (any operator label set at pair import)")
    p_send.add_argument("--text", required=True, help="message text (1-160 UTF-8 bytes)")
    p_send.add_argument("--send-timeout", dest="timeout", type=float, default=serial_link.SEND_TIMEOUT, help="outcome deadline in seconds (covers bounded retries)")

    p_listen = sub.add_parser("listen", help="receive loop (single owner; second opener gets PORT_BUSY)")
    p_listen.add_argument("--seconds", type=float, default=None, help="stop after N seconds (default: until Ctrl-C)")

    p_chat = sub.add_parser("chat", help="interactive chat (single owner)")
    p_chat.add_argument("--contact", default=None, help="initial send target")

    sub.add_parser("tui", help="terminal station console (all boards, Tab to cycle)")

    sub.add_parser("contacts", help="list contact slots with local names")

    p_block = sub.add_parser("block", help="block a paired contact")
    p_block.add_argument("contact", help="paired contact name")
    p_unblock = sub.add_parser("unblock", help="unblock a paired contact")
    p_unblock.add_argument("contact", help="paired contact name")
    p_delete = sub.add_parser("contact-delete", help="delete a paired contact (frees slot)")
    p_delete.add_argument("contact", help="paired contact name")
    p_settings = sub.add_parser("settings", help="tunable TX/relay params (firmware-clamped; RF applies next radio-on)")
    p_settings.add_argument("key", nargs="?", default=None, help="tx_power|max_tx|ack_wait|relay_ttl|relay_jitter|cad_attempts|sync_word (omit to list all)")
    p_settings.add_argument("value", nargs="?", type=int, default=None, help="new value (omit to read; out-of-range clamps)")

    p_wifi = sub.add_parser("wifi", help="WiFi credential for the TCP transport (passphrase never shown)")
    wifi_sub = p_wifi.add_subparsers(dest="wifi_cmd", required=True)
    wifi_sub.add_parser("status", help="report configured + ssid_len (never secrets)")
    p_wifi_set = wifi_sub.add_parser("set", help="store credential (firmware joins live)")
    p_wifi_set.add_argument("--ssid", required=True, help="network name (1-32 chars)")
    p_wifi_set.add_argument("--pass", dest="passwd", default="", help="passphrase (0-63 chars; empty means open network)")
    wifi_sub.add_parser("forget", help="clear the stored credential")
    p_pair = sub.add_parser("pair", help="in-person pairing (radio stays off)")
    pair_sub = p_pair.add_subparsers(dest="pair_cmd", required=True)
    for kind in ("offer", "proof", "confirm"):
        p_exp = pair_sub.add_parser(kind, help=f"export {kind} as QR PNG")
        p_exp.add_argument("--out", required=True, help="output PNG path")
    p_imp = pair_sub.add_parser("import", help="import a peer QR PNG")
    p_imp.add_argument("--file", required=True, help="peer PNG path")
    p_imp.add_argument("--name", required=True, help="local display name for the contact (any label, e.g. alice, relay-2)")
    p_imp.add_argument("--replace", action="store_true", help="replace an existing contact slot")
    cli_extra.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "timeout"):
        args.timeout = serial_link.DEFAULT_TIMEOUT
    try:
        args.timeout = min(max(float(args.timeout), 0.5), serial_link.MAX_TIMEOUT)
    except (TypeError, ValueError):
        print("meshctl: error: --timeout must be a number", file=sys.stderr)
        return 2
    if args.cmd in ("ports", "boards", "tui", "flash", "elf", "uf2", "reboot", "records"):
        pass
    elif getattr(args, "transport", "usb") == "tcp":
        pass
    elif not args.port:
        print("meshctl: error: --port is required for --transport usb (except for ports, boards, tui, flash, elf, uf2, reboot, records)", file=sys.stderr)
        return 2
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "ports":
        return cmd_ports(args)
    if args.cmd == "provision":
        return cmd_provision(args)
    if args.cmd == "time":
        return cmd_time(args)
    if args.cmd == "radio":
        return cmd_radio(args)
    if args.cmd == "ping":
        return cmd_ping(args)
    if args.cmd == "send":
        return cmd_send(args)
    if args.cmd == "listen":
        return cmd_listen(args)
    if args.cmd == "chat":
        return cmd_chat(args)
    if args.cmd == "tui":
        from .tui import cmd_tui
        return cmd_tui(args)
    if args.cmd == "contacts":
        return cmd_contacts(args)
    if args.cmd == "settings":
        return cmd_settings(args)
    if args.cmd == "wifi":
        return cmd_wifi(args)
    if args.cmd == "block":
        return cmd_block(args, True)
    if args.cmd == "unblock":
        return cmd_block(args, False)
    if args.cmd == "contact-delete":
        return cmd_delete(args)
    if args.cmd == "pair":
        if args.pair_cmd in ("offer", "proof", "confirm"):
            return cmd_pair_export(args)
        return cmd_pair_import(args)
    extra = cli_extra.dispatch(args)
    if extra is not None:
        return extra
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
