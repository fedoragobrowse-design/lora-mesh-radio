"""Extended CLI commands: boards, flash, ELF/UF2, debug, records, history.

All device access stays sudo-free: BOOTSEL flashing goes through the
USB mass-storage volume, ``picotool`` file subcommands need no device,
and live-device commands report PERMISSION instead of escalating.
Board selection is by USB serial/label/device — never bare ttyACM.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _err(msg: str) -> int:
    print(f"meshctl: error: {msg}", file=sys.stderr)
    return 1


def cmd_boards(args: argparse.Namespace) -> int:
    """Discover + probe every CDC node (one matched-ID status each)."""
    from . import boards as _boards

    found = _boards.probe_all(timeout=args.timeout)
    if not found:
        print("no CDC mesh nodes (check USB cables; BOOTSEL volumes are not CDC)")
        return 0
    for board in found:
        if board.error:
            print(f"{board.serial[:8]}\t{board.device}\terror={board.error}")
            continue
        print(f"{board.label or '?'}\t{board.serial}\t{board.device}\t"
              f"{board.image} radio={'on' if board.radio_enabled else 'off'} "
              f"avail={board.radio_available} rv={board.radio_version} "
              f"epoch={board.epoch} contacts={board.contacts.get('count', '?')}")
    return 0


def _resolve_board(args: argparse.Namespace):
    """Board by --board serial/label/device; None + error message on failure."""
    from . import boards as _boards

    found = _boards.probe_all(timeout=args.timeout)
    if not args.board:
        if len(found) == 1 and not found[0].error:
            return found[0], ""
        return None, ("ambiguous: multiple boards; pass --board SERIAL/LABEL/DEVICE "
                      "(see `meshctl boards`)")
    board = _boards.find_board(found, args.board)
    if board is None:
        return None, f"no board matches {args.board!r} (see `meshctl boards`)"
    if board.error:
        return None, f"board {args.board!r}: {board.error}"
    return board, ""


def _board_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--board", default=None,
                        help="USB serial (prefix ok), label A/B/C, or device path")


def cmd_flash(args: argparse.Namespace) -> int:
    """Sudo-free UF2 flash to exactly one BOOTSEL volume (or --dev)."""
    from . import boards as _boards
    from . import device as _device

    uf2 = Path(args.uf2)
    if not uf2.is_file():
        return _err(f"no such UF2: {args.uf2}")
    if args.dev:
        dev = args.dev
    else:
        volumes = _boards.bootsel_volumes()
        if len(volumes) != 1:
            return _err(f"need exactly 1 BOOTSEL volume, saw {len(volumes)} "
                        "(put one board in BOOTSEL, or pass --dev)")
        dev = volumes[0].dev
    try:
        mount = _device.mount_bootsel(dev)
        result = _device.flash_uf2(str(uf2), mount)
    except (ValueError, RuntimeError) as exc:
        return _err(str(exc))
    print(f"flashed {result.bytes_copied}B -> {result.volume} "
          f"rebooted_to_app={result.rebooted_to_app}")
    if not result.rebooted_to_app:
        return _err("board did not reboot yet; wait and re-run `meshctl boards`")
    return 0


def cmd_elf(args: argparse.Namespace) -> int:
    """Static ELF check or picotool file info (no USB, no sudo)."""
    from . import device as _device

    if args.elf_cmd == "check":
        try:
            result = _device.check_elf(args.file)
        except (OSError, ValueError) as exc:
            return _err(f"ELF check FAIL: {exc}")
        print(f"PASS entry=0x{result['entry']:08x} reset=0x{result['reset']:08x} "
              f"stack=0x{result['stack']:08x} stored={result['stored_bytes']}B "
              f"segs={result['load_segments']} (top 64KiB untouched)")
        return 0
    try:
        print(_device.info_file(args.file, args.type), end="")
    except RuntimeError as exc:
        return _err(str(exc))
    return 0


def cmd_uf2(args: argparse.Namespace) -> int:
    """ELF -> UF2 conversion (no USB, no sudo)."""
    from . import device as _device

    try:
        _device.uf2_convert(args.elf, args.out)
    except RuntimeError as exc:
        return _err(str(exc))
    print(f"wrote {args.out}")
    return 0


def cmd_reboot(args: argparse.Namespace) -> int:
    """Live reboot into app or BOOTSEL (needs raw USB; PERMISSION-aware)."""
    from . import device as _device

    try:
        out = _device.live_command("reboot", "-u" if args.bootsel else "-a")
    except RuntimeError as exc:
        return _err(str(exc))
    print(out.strip()[:200])
    return 0


def cmd_debug_log(args: argparse.Namespace) -> int:
    """Raw CDC line dump: every line verbatim, framing diagnostics visible."""
    from . import serial_link as _sl

    port = args.port
    try:
        session = _sl.SerialSession(port).open()
    except _sl.PortBusyError:
        return _err(f"PORT_BUSY: {port} owned elsewhere")
    except (RuntimeError, OSError) as exc:
        return _err(str(exc))
    deadline = time.monotonic() + args.seconds if args.seconds else None
    print(f"raw log on {port} (Ctrl-C to stop)...", file=sys.stderr)
    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                obj = session.read_next(timeout=1.0)
            except _sl.TimeoutError as exc:
                print(f"note: {exc}", file=sys.stderr)
                continue
            if obj is not None:
                print(json.dumps(obj, ensure_ascii=False))
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
    return 0
def cmd_debug_counters(args: argparse.Namespace) -> int:
    from . import serial_link as _sl

    port = args.port
    try:
        session = _sl.SerialSession(port).open()
    except _sl.PortBusyError:
        return _err(f"PORT_BUSY: {port} owned elsewhere")
    except (RuntimeError, OSError) as exc:
        return _err(str(exc))
    previous: dict | None = None
    try:
        for round_no in range(args.rounds):
            try:
                reply, _ = session.exchange("status", None, args.timeout)
            except (_sl.TimeoutError, ValueError, RuntimeError, OSError) as exc:
                return _err(str(exc))
            if not reply.get("ok"):
                return _err(f"firmware error: {reply.get('error', 'UNKNOWN')}")
            counters = reply.get("result", {}).get("counters", {})
            if previous is None:
                print("base: " + json.dumps(counters, sort_keys=True))
            else:
                delta = {k: counters.get(k, 0) - previous.get(k, 0)
                         for k in counters if isinstance(counters.get(k), int)}
                moved = {k: v for k, v in delta.items() if v}
                print(f"+{args.interval:.0f}s: "
                      + (json.dumps(moved, sort_keys=True) if moved else "no movement"))
            previous = dict(counters)
            if round_no + 1 < args.rounds:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
    return 0


def cmd_records(args: argparse.Namespace) -> int:
    """List or prune QR audit records under .mesh-local/records/."""
    from . import local as _local

    records = _local.records_dir()
    files = sorted(records.glob("*.txt")) + sorted(records.glob("*.png"))
    if args.records_cmd == "list":
        for path in files:
            print(f"{path.stat().st_size:6d}  {path.name}")
        print(f"{len(files)} file(s)")
        return 0
    keep = max(args.keep, 0)
    victims = files[: max(len(files) - keep, 0)] if keep else files
    for path in victims:
        try:
            path.unlink()
        except OSError as exc:
            return _err(f"cannot remove {path.name}: {exc}")
    print(f"pruned {len(victims)} file(s), kept {len(files) - len(victims)}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Read local per-port message history (newest first)."""
    from . import history as _history
    from . import local as _local

    try:
        conn = _history.open_history(_local.history_path_for(args.port))
    except OSError as exc:
        return _err(str(exc))
    try:
        rows = _history.recent_messages(conn, args.limit)
    except (ValueError, OSError, RuntimeError) as exc:
        return _err(str(exc))
    finally:
        conn.close()
    for contact, direction, epoch, sequence, text in rows:
        arrow = "->" if direction == "out" else "<-"
        print(f"[{contact} {arrow} e{epoch} s{sequence}] {text}")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    """Add extended subcommands (called from __main__ parser builder)."""
    from . import serial_link as _sl

    p_boards = sub.add_parser("boards", help="discover + probe nodes by USB serial")
    p_boards.add_argument("--timeout", type=float, default=_sl.DEFAULT_TIMEOUT)

    p_flash = sub.add_parser("flash", help="sudo-free UF2 flash to BOOTSEL volume")
    p_flash.add_argument("--uf2", required=True, help="firmware .uf2 path")
    p_flash.add_argument("--dev", default=None, help="BOOTSEL partition (default: auto, exactly 1)")

    p_elf = sub.add_parser("elf", help="firmware image inspection (no USB)")
    elf_sub = p_elf.add_subparsers(dest="elf_cmd", required=True)
    p_check = elf_sub.add_parser("check", help="static RP2350 ELF checks")
    p_check.add_argument("file", help="firmware .elf path")
    p_info = elf_sub.add_parser("info", help="picotool info on a file")
    p_info.add_argument("file", help="image path")
    p_info.add_argument("--type", default="elf", help="image type (default elf)")

    p_uf2 = sub.add_parser("uf2", help="UF2 conversion (no USB)")
    p_uf2.add_argument("elf", help="input .elf")
    p_uf2.add_argument("--out", required=True, help="output .uf2")

    p_reboot = sub.add_parser("reboot", help="live reboot (needs raw USB)")
    p_reboot.add_argument("--bootsel", action="store_true", help="reboot into BOOTSEL storage")

    p_debug = sub.add_parser("debug", help="Pico/UART diagnostics")
    dbg_sub = p_debug.add_subparsers(dest="debug_cmd", required=True)
    p_log = dbg_sub.add_parser("log", help="raw CDC line dump")
    p_log.add_argument("--seconds", type=float, default=None)
    p_counters = dbg_sub.add_parser("counters", help="poll counters, show deltas")
    p_counters.add_argument("--rounds", type=int, default=3)
    p_counters.add_argument("--interval", type=float, default=10.0)
    p_counters.add_argument("--timeout", type=float, default=_sl.DEFAULT_TIMEOUT)

    p_records = sub.add_parser("records", help="QR audit record files")
    rec_sub = p_records.add_subparsers(dest="records_cmd", required=True)
    rec_sub.add_parser("list", help="list record files")
    p_prune = rec_sub.add_parser("prune", help="delete oldest record files")
    p_prune.add_argument("--keep", type=int, default=20, help="newest files to keep")

    p_history = sub.add_parser("history", help="local per-port message history")
    p_history.add_argument("--port", required=True)
    p_history.add_argument("--limit", type=int, default=20)


def dispatch(args: argparse.Namespace):
    """Route extended commands; returns int or None when not ours."""
    if args.cmd == "boards":
        return cmd_boards(args)
    if args.cmd == "flash":
        return cmd_flash(args)
    if args.cmd == "elf":
        return cmd_elf(args)
    if args.cmd == "uf2":
        return cmd_uf2(args)
    if args.cmd == "reboot":
        return cmd_reboot(args)
    if args.cmd == "debug":
        if args.debug_cmd == "log":
            return cmd_debug_log(args)
        return cmd_debug_counters(args)
    if args.cmd == "records":
        return cmd_records(args)
    if args.cmd == "history":
        return cmd_history(args)
    return None
