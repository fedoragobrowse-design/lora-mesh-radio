// mesh webapp: sidebar threads -> bubble pane -> input bar. No build step.
"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  boards: [], serial: "", contact: "", cursor: 0,
  msgs: new Map(),  // "serial|contact" -> [{direction, text, state}]
  unread: new Map(), pending: [], timer: null,
};
const TICKS = { queued: "◷", sent: "✓", acked: "✓✓", failed: "✗" };
const key = (s, c) => s + "|" + c;

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

function threadList(serial) {
  const b = state.boards.find((x) => x.serial === serial);
  const names = [];
  if (b) for (const n of b.threads || []) if (!names.includes(n)) names.push(n);
  for (const k of state.msgs.keys()) {
    const [s, c] = k.split("|");
    if (s === serial && !names.includes(c)) names.push(c);
  }
  return names;
}

function renderSidebar() {
  const box = $("threads");
  box.innerHTML = "";
  for (const b of state.boards) {
    const h = document.createElement("div");
    h.className = "board";
    const radio = b.radio_enabled ? "ON" : "OFF";
    h.textContent = `${b.label} · ⏱${b.time_valid ? "ok" : "--"} · radio ${radio}`;
    box.appendChild(h);
    for (const name of threadList(b.serial)) {
      const row = document.createElement("div");
      const sel = b.serial === state.serial && name === state.contact;
      row.className = "thread" + (sel ? " sel" : "");
      const unread = state.unread.get(key(b.serial, name)) || 0;
      row.innerHTML = "";
      row.appendChild(document.createTextNode(name + " "));
      if (unread) {
        const s = document.createElement("span");
        s.className = "badge";
        s.textContent = `(${unread})`;
        row.appendChild(s);
      }
      row.onclick = () => select(b.serial, name);
      box.appendChild(row);
    }
  }
  if (!state.boards.length) {
    box.innerHTML = "<p>No stations. Start <code>python3 webapp/serve.py</code> " +
      "with boards plugged in, then reload.</p>";
  }
}

function renderHead() {
  const b = state.boards.find((x) => x.serial === state.serial);
  if (!b) { $("title").textContent = "mesh webapp"; $("sub").textContent = "pick a thread"; return; }
  const c = b.counters || {};
  $("title").textContent = `${b.label} → ${state.contact || "no thread"}`;
  $("sub").textContent = `epoch ${b.epoch} ${b.time_valid ? "⏱ok" : "⏱--"} · ` +
    `radio ${b.radio_enabled ? "ON" : "OFF"} · tx ${c.tx_ok ?? c.tx ?? "?"} / ` +
    `rx ${c.rx_ok ?? c.rx ?? "?"} · serial ${b.serial.slice(0, 8)}`;
}

function renderLog() {
  const log = $("log");
  log.innerHTML = "";
  const msgs = state.msgs.get(key(state.serial, state.contact)) || [];
  for (const m of msgs.slice(-200)) {
    const d = document.createElement("div");
    d.className = "bubble " + m.direction;
    if (m.direction === "in") {
      const who = document.createElement("span");
      who.className = "who";
      who.textContent = "←";
      d.appendChild(who);
      d.appendChild(document.createTextNode(m.text));
    } else {
      d.appendChild(document.createTextNode(m.text));
      const t = document.createElement("span");
      t.className = "tick";
      t.textContent = TICKS[m.state] || "?";
      d.appendChild(t);
    }
    log.appendChild(d);
  }
  log.scrollTop = log.scrollHeight;
}

function select(serial, contact) {
  state.serial = serial;
  state.contact = contact;
  state.unread.set(key(serial, contact), 0);
  renderSidebar(); renderHead(); renderLog();
  loadHistory();
}

async function loadHistory() {
  if (!state.serial || !state.contact) return;
  const q = `/api/history?serial=${encodeURIComponent(state.serial)}` +
    `&contact=${encodeURIComponent(state.contact)}&limit=50`;
  let data = {};
  try { data = await api(q); } catch { return; }
  if (!data.ok) return;
  const k = key(state.serial, state.contact);
  const live = state.msgs.get(k) || [];
  const liveTexts = new Set(live.map((m) => m.direction + "|" + m.text));
  const rows = (data.messages || [])
    .filter((m) => !liveTexts.has(m.direction + "|" + m.text))
    .map((m) => ({ direction: m.direction, text: m.text,
                   state: m.direction === "in" ? "in" : "acked" }));
  state.msgs.set(k, rows.concat(live).slice(-200));
  renderLog();
}

function pushMsg(serial, contact, direction, text, st) {
  const k = key(serial, contact);
  const arr = state.msgs.get(k) || [];
  arr.push({ direction, text: text.slice(0, 300), state: st });
  state.msgs.set(k, arr.slice(-200));
  if (serial === state.serial && contact === state.contact) { renderLog(); }
  else {
    state.unread.set(k, (state.unread.get(k) || 0) + 1);
    renderSidebar();
  }
}

function markTick(serial, status, replyText) {
  // ACKNOWLEDGED -> newest queued/sent bubble becomes acked (✓✓);
  // UNCONFIRMED -> newest queued/sent bubble becomes failed (✗).
  const want = status === "ACKNOWLEDGED" ? "acked" : "failed";
  for (const [k, arr] of state.msgs) {
    if (!k.startsWith(serial + "|")) continue;
    for (let i = arr.length - 1; i >= 0; i--) {
      const m = arr[i];
      if (m.direction === "out" && (m.state === "sent" || m.state === "queued")) {
        m.state = want;
        const [s, c] = k.split("|");
        if (s === state.serial && c === state.contact) renderLog();
        return;
      }
    }
  }
  void replyText;
}

async function poll() {
  let data = {};
  try { data = await api(`/api/events?cursor=${state.cursor}`); }
  catch { return; }
  if (!data.ok) return;
  state.cursor = data.cursor || state.cursor;
  let boardsDirty = false;
  for (const e of data.events || []) {
    if (e.type === "msg" && e.direction === "in") {
      pushMsg(e.serial, e.contact, "in", e.text, "in");
    } else if (e.type === "tick") {
      markTick(e.serial, e.status, e.text);
    } else if (e.type === "boards") {
      boardsDirty = true;
    }
  }
  if (boardsDirty) await refreshBoards(false);
}

async function refreshBoards(reselect = true) {
  let data = {};
  try { data = await api("/api/boards"); } catch { return; }
  if (!data.ok) return;
  const had = state.serial;
  state.boards = data.boards || [];
  // Merge server-side thread names into the local map so empty
  // threads (history only) still appear in the sidebar.
  for (const b of state.boards) {
    for (const n of b.threads || []) {
      const k = key(b.serial, n);
      if (!state.msgs.has(k)) state.msgs.set(k, []);
    }
  }
  if (reselect && (!had || !state.boards.some((b) => b.serial === had))) {
    const first = state.boards[0];
    if (first) {
      state.serial = first.serial;
      state.contact = threadList(first.serial)[0] || "";
      await loadHistory();
    }
  }
  renderSidebar(); renderHead();
}

async function send() {
  const text = $("text").value;
  if (!text.trim() || !state.serial || !state.contact) return;
  pushMsg(state.serial, state.contact, "out", text, "sent");
  $("text").value = "";
  try {
    const data = await api("/api/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ serial: state.serial, contact: state.contact, text }),
    });
    if (!data.ok) {
      const arr = state.msgs.get(key(state.serial, state.contact)) || [];
      const last = [...arr].reverse().find((m) => m.direction === "out");
      if (last) last.state = "failed";
      renderLog();
      alert(data.error || "send failed");
    }
  } catch (e) { alert("bridge unreachable: " + e); }
}

async function op(name) {
  if (!state.serial) return;
  const map = {
    status: ["status", null], contacts: ["contacts", null],
    radio_on: ["radio_set", { enabled: true }],
    radio_off: ["radio_set", { enabled: false }],
  };
  const [opName, params] = map[name] || [];
  if (!opName) return;
  await api("/api/op", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ serial: state.serial, op: opName, params }),
  });
}

async function boot() {
  $("helpclose").onclick = () => { $("help").style.display = "none"; };
  $("send").onclick = send;
  $("text").addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });
  $("newthread").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const name = $("newthread").value.trim();
    if (!name || !state.serial) return;
    if (name.length > 32) { alert("name must be 1-32 chars"); return; }
    const k = key(state.serial, name);
    if (!state.msgs.has(k)) state.msgs.set(k, []);
    $("newthread").value = "";
    select(state.serial, name);
  });
  for (const b of document.querySelectorAll("#ops button")) {
    b.onclick = () => op(b.dataset.op);
  }
  await refreshBoards(true);
  renderLog();
  state.timer = setInterval(poll, 1000);
}
document.addEventListener("DOMContentLoaded", boot);
