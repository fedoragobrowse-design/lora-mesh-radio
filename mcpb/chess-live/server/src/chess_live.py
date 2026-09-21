"""chess-live: companion MCP server pairing chess tools with a live board page.

Complements the existing chess-muserelf engine (game logic stays there).
This server keeps its own games via python-chess and serves each board as
an auto-refreshing page at http://127.0.0.1:8765/board/<game_id> so the
user can watch a live game in a browser. Use set_fen to mirror an
external (e.g. muserelf) position into the live view.
"""
from __future__ import annotations

import html
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import chess
import chess.svg
from fastmcp import FastMCP

PORT = int(os.environ.get("CHESS_LIVE_PORT", "8765"))
STATE_FILE = os.environ.get(
    "CHESS_LIVE_STATE", "/home/gobrowse/code/LoRa_Mesh_Handoff/.mesh-local/chess-live.json"
)

mcp = FastMCP("chess-live")
GAMES: dict[str, chess.Board] = {}
_LOCK = threading.RLock()

GAME_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_GAMES = 64
MAX_MOVES = 600  # absolute ceiling on stored plies per game
MAX_FEN_LEN = 200
MAX_MOVE_LEN = 16


def _check_game_id(game_id: str) -> str | None:
    """Return an error string when game_id is unacceptable, else None."""
    if not isinstance(game_id, str) or not GAME_ID_RE.match(game_id):
        return "game_id must match [A-Za-z0-9_-]{1,64}"
    return None


def _load() -> None:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    loaded: dict[str, chess.Board] = {}
    if not isinstance(data, dict):
        return
    for game_id, entry in list(data.items())[:MAX_GAMES]:
        if _check_game_id(game_id) or not isinstance(entry, (dict, str)):
            continue
        try:
            if isinstance(entry, dict):
                moves = entry.get("moves", [])
                if not isinstance(moves, list):
                    continue
                if moves:  # native game: replay UCI history from start
                    board = chess.Board()
                    for uci in moves[:MAX_MOVES]:
                        board.push_uci(uci)
                else:  # mirrored FEN: position only, no history to replay
                    fen = entry.get("fen", chess.STARTING_FEN)
                    if not isinstance(fen, str) or len(fen) > MAX_FEN_LEN:
                        continue
                    board = chess.Board(fen)
                loaded[game_id] = board
            else:  # legacy FEN-only entry
                if len(entry) > MAX_FEN_LEN:
                    continue
                loaded[game_id] = chess.Board(entry)
        except ValueError:
            continue
    with _LOCK:
        GAMES.clear()
        GAMES.update(loaded)


def _save() -> None:
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with _LOCK:
            payload = {
                g: {"fen": b.fen(), "moves": [m.uci() for m in b.move_stack]}
                for g, b in list(GAMES.items())[:MAX_GAMES]
            }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass

_load()


def board_url(game_id: str) -> str:
    return f"http://127.0.0.1:{PORT}/board/{game_id}"


def _snapshot(game_id: str, board: chess.Board) -> dict:
    return {
        "ok": True,
        "game_id": game_id,
        "fen": board.fen(),
        "turn": "white" if board.turn == chess.WHITE else "black",
        "ascii": str(board),
        "moves_san": _moves_san(board),
        "is_over": board.is_game_over(),
        "result": board.result(),
        "board_url": board_url(game_id),
    }


def _moves_san(board: chess.Board) -> list[str]:
    tmp = chess.Board()
    out = []
    for m in board.move_stack:
        out.append(tmp.san(m))
        tmp.push(m)
    return out


@mcp.tool
def new_game(game_id: str = "live-1") -> dict:
    """Start a new game (White to move). Returns FEN plus live board URL."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    with _LOCK:
        if game_id not in GAMES and len(GAMES) >= MAX_GAMES:
            return {"ok": False, "error": f"too many games (max {MAX_GAMES})"}
        GAMES[game_id] = chess.Board()
        board = GAMES[game_id]
    _save()
    return _snapshot(game_id, board)


@mcp.tool
def set_fen(game_id: str, fen: str) -> dict:
    """Mirror an external position (e.g. from the muserelf engine) into the live view. Note: a FEN carries no move history, so the mirrored game starts a fresh move list from this position."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    if not isinstance(fen, str) or len(fen) > MAX_FEN_LEN:
        return {"ok": False, "error": "fen too long or not a string"}
    try:
        board = chess.Board(fen)
    except ValueError:
        return {"ok": False, "error": "invalid FEN"}
    with _LOCK:
        if game_id not in GAMES and len(GAMES) >= MAX_GAMES:
            return {"ok": False, "error": f"too many games (max {MAX_GAMES})"}
        GAMES[game_id] = board
    _save()
    return _snapshot(game_id, board)


@mcp.tool
def play_move(game_id: str, move: str) -> dict:
    """Play a move (SAN like 'Nf3' or UCI like 'g1f3'). Returns updated position."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    if not isinstance(move, str) or len(move) > MAX_MOVE_LEN:
        return {"ok": False, "error": "move too long or not a string"}
    with _LOCK:
        board = GAMES.get(game_id)
        if board is None:
            return {"ok": False, "error": f"unknown game '{game_id}'; call new_game first"}
        if len(board.move_stack) >= MAX_MOVES:
            return {"ok": False, "error": "game too long; start a new game"}
        try:
            try:
                parsed = board.parse_san(move)
            except ValueError:
                parsed = board.parse_uci(move)
        except ValueError:
            return {"ok": False, "error": "illegal move"}
        san = board.san(parsed)
        board.push(parsed)
    _save()
    snap = _snapshot(game_id, board)
    snap["played"] = san
    return snap


@mcp.tool
def legal_moves(game_id: str) -> dict:
    """List all legal moves (UCI and SAN) for the side to move."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    with _LOCK:
        board = GAMES.get(game_id)
        if board is None:
            return {"ok": False, "error": f"unknown game '{game_id}'"}
        moves = [{"uci": m.uci(), "san": board.san(m)} for m in board.legal_moves]
        turn = "white" if board.turn == chess.WHITE else "black"
    return {"ok": True, "turn": turn, "moves": moves}


@mcp.tool
def status(game_id: str = "live-1") -> dict:
    """Current position: FEN, ASCII board, move history, result, live URL."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    with _LOCK:
        board = GAMES.get(game_id)
        if board is None:
            return {"ok": False, "error": f"unknown game '{game_id}'"}
    snap = _snapshot(game_id, board)
    return snap


@mcp.tool
def board_link(game_id: str = "live-1") -> dict:
    """Return the watch-in-browser URL for a game."""
    if err := _check_game_id(game_id):
        return {"ok": False, "error": err}
    return {"ok": True, "game_id": game_id, "board_url": board_url(game_id)}




def _page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>{html.escape(title)}</title>
<style>body{{font:14px system-ui;background:#161512;color:#eee;margin:20px}}
a{{color:#8ab4f8}}pre{{line-height:1.1;font-size:16px}}</style>
</head><body>{body}</body></html>""".encode()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def do_GET(self):
        _load()
        url = urlparse(self.path)
        if url.path == "/" or url.path == "/board":
            qs = parse_qs(url.query)
            if "fen" in qs:
                fen = qs["fen"][0]
                if len(fen) > MAX_FEN_LEN:
                    self._send(400, _page("bad fen", "<p>invalid FEN</p>"))
                    return
                try:
                    board = chess.Board(fen)
                except ValueError:
                    self._send(400, _page("bad fen", "<p>invalid FEN</p>"))
                    return
                svg = chess.svg.board(board, size=420)
                self._send(200, _page("live board", f"{svg}<pre>{html.escape(board.fen())}</pre>"))
                return
            with _LOCK:
                rows = sorted((g, b.fen()) for g, b in GAMES.items())
            items = "".join(
                f'<li><a href="/board/{html.escape(g)}">{html.escape(g)}</a> — {html.escape(f)}</li>'
                for g, f in rows
            ) or "<li>no games yet — call new_game</li>"
            self._send(200, _page("chess-live", "<h1>live games</h1><ul>" + items + "</ul>"))
            return
        if url.path.startswith("/board/"):
            game_id = url.path[len("/board/"):]
            if _check_game_id(game_id):
                self._send(404, _page("missing", "<p>unknown game</p>"))
                return
            with _LOCK:
                board = GAMES.get(game_id)
                san_list = _moves_san(board) if board is not None else []
                snapshot = (board.fen(), board.turn, board.is_game_over(), board.result()) if board is not None else None
            if board is None or snapshot is None:
                self._send(404, _page("missing", "<p>unknown game</p>"))
                return
            fen, turn, over, result = snapshot
            svg = chess.svg.board(board, size=420)
            san = " ".join(
                f"{i // 2 + 1}.{html.escape(m)}" if i % 2 == 0 else html.escape(m)
                for i, m in enumerate(san_list)
            )
            side = "white" if turn == chess.WHITE else "black"
            self._send(
                200,
                _page(
                    game_id,
                    f"<h1>{html.escape(game_id)} — {side} to move</h1>{svg}"
                    f"<pre>{san or '(no moves yet)'}</pre>"
                    f"<pre>{html.escape(result) if over else '*'}</pre>",
                ),
            )
            return
        self._send(404, _page("missing", "<p>not found</p>"))

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)


def _serve():
    try:
        HTTPServer(("127.0.0.1", PORT), _Handler).serve_forever()
    except OSError:
        pass  # another chess-live owns the port; tools still work


threading.Thread(target=_serve, daemon=True).start()


if __name__ == "__main__":
    mcp.run()
