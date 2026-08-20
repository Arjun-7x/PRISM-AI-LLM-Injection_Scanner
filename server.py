"""
Backend for the injection scanner console.

Serves the static UI and exposes:
    GET  /api/status   - is the AI layer configured, which provider/model, signature count
    POST /api/scan      - run a prompt through PromptInjectionScanner
    GET  /api/history   - recent scan verdicts (in-memory, capped)
    GET  /api/stats      - aggregate counts for the dashboard
    DELETE /api/history - clear stored history/stats

Run:
    pip install -r requirements.txt
    export GROQ_API_KEY=gsk_...        # OR export ANTHROPIC_API_KEY=sk-ant-...
    python server.py
    # open http://localhost:5000
"""

import os
import time
import threading
from collections import deque, defaultdict

from flask import Flask, request, jsonify, send_from_directory

from prompt_injection_scanner import (
    PromptInjectionScanner,
    RegexScanner,
    build_ai_scanner_from_env,
)

app = Flask(__name__, static_folder="static", static_url_path="")

MAX_PROMPT_LEN = 4000
HISTORY_LIMIT = 200
RATE_LIMIT_PER_MIN = 30

# By default, X-Forwarded-For is NOT trusted: it's a client-supplied header
# and anyone can set it to bypass the per-IP rate limit. Only honor it if
# this app is actually deployed behind a proxy that sets/overwrites it
# (nginx, a load balancer, etc.) — opt in explicitly via env var.
TRUST_X_FORWARDED_FOR = os.environ.get("TRUST_X_FORWARDED_FOR", "false").lower() == "true"

ai_scanner = build_ai_scanner_from_env(dict(os.environ))
scanner = PromptInjectionScanner(ai_scanner=ai_scanner)

# --------------------------------------------------------------------------
# In-memory history + stats (resets on restart; this is a demo/portfolio
# app, not a durable store — swap for a real DB before production use).
# --------------------------------------------------------------------------
_lock = threading.Lock()
_history: deque = deque(maxlen=HISTORY_LIMIT)
_stats = {
    "total": 0,
    "injections": 0,
    "benign": 0,
    "intent_counts": defaultdict(int),
}

# very small fixed-window rate limiter, per client IP
_rate_buckets: dict[str, list[float]] = defaultdict(list)
_last_evict = 0.0
_EVICT_INTERVAL = 60  # seconds between sweeps
_RATE_BUCKET_CAP = 50_000  # hard safety cap on distinct IPs tracked


def _evict_stale_buckets(now: float) -> None:
    """
    Drops rate-limit buckets for IPs that haven't made a request in over a
    minute. Without this, _rate_buckets grows for every distinct IP ever
    seen and never shrinks — a slow memory leak under sustained traffic
    from many unique clients, separate from the documented in-memory
    history/stats limitation.
    """
    global _last_evict
    if now - _last_evict < _EVICT_INTERVAL:
        return
    _last_evict = now
    window_start = now - 60
    stale = [ip for ip, bucket in _rate_buckets.items()
             if not bucket or max(bucket) <= window_start]
    for ip in stale:
        del _rate_buckets[ip]
    # Extra safety valve: if something pathological is still filling the
    # dict (e.g. an attacker cycling through huge numbers of spoofed IPs
    # within a single window), drop the oldest-looking entries rather than
    # growing without bound.
    if len(_rate_buckets) > _RATE_BUCKET_CAP:
        overflow = len(_rate_buckets) - _RATE_BUCKET_CAP
        for ip in list(_rate_buckets.keys())[:overflow]:
            del _rate_buckets[ip]


def _client_ip() -> str:
    """
    Returns the IP to key the rate limiter on.

    request.remote_addr (the actual TCP peer) is used unless this app is
    deployed behind a trusted reverse proxy that sets X-Forwarded-For
    itself, in which case TRUST_X_FORWARDED_FOR=true can be set so the
    real client IP (not the proxy's) is used. Without that trust
    relationship, X-Forwarded-For is attacker-controlled and trusting it
    lets anyone bypass the per-IP rate limit by sending a fresh value on
    every request.
    """
    if TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Left-most entry is the original client per the standard
            # convention; a trusted proxy appends to the right.
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _rate_limited(ip: str) -> bool:
    now = time.time()
    _evict_stale_buckets(now)
    window_start = now - 60
    bucket = _rate_buckets[ip]
    bucket[:] = [t for t in bucket if t > window_start]
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return True
    bucket.append(now)
    return False


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "ai_available": scanner.ai_available,
        "provider": ai_scanner.provider if ai_scanner else None,
        "model": ai_scanner.model if ai_scanner else None,
        "signature_count": RegexScanner.signature_count(),
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    ip = _client_ip()
    if _rate_limited(ip):
        return jsonify({"error": "rate limit exceeded, try again shortly"}), 429

    payload = request.get_json(force=True, silent=True) or {}
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "prompt is required"}), 400
    if len(prompt) > MAX_PROMPT_LEN:
        return jsonify({"error": f"prompt too long (max {MAX_PROMPT_LEN} characters)"}), 413

    verdict = scanner.scan(prompt)
    result = verdict.to_dict()

    with _lock:
        _history.appendleft({"prompt": prompt[:300], "verdict": result})
        _stats["total"] += 1
        _stats["injections" if verdict.is_injection else "benign"] += 1
        _stats["intent_counts"][verdict.intent.value] += 1

    return jsonify(result)


@app.route("/api/history")
def history():
    with _lock:
        return jsonify({"entries": list(_history)})


@app.route("/api/stats")
def stats():
    with _lock:
        total = _stats["total"]
        block_rate = (_stats["injections"] / total) if total else 0.0
        return jsonify({
            "total": total,
            "injections": _stats["injections"],
            "benign": _stats["benign"],
            "block_rate": round(block_rate, 4),
            "intent_counts": dict(_stats["intent_counts"]),
        })


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    with _lock:
        _history.clear()
        _stats["total"] = 0
        _stats["injections"] = 0
        _stats["benign"] = 0
        _stats["intent_counts"] = defaultdict(int)
    return jsonify({"cleared": True})


if __name__ == "__main__":
    app.run(debug=False, port=5000)
