#!/usr/bin/env python3
"""Desktop-friendly WiFind launcher for packaged builds."""

from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from http.server import ThreadingHTTPServer

from web_app import WiFindHandler, require_admin


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch WiFind and open the local dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind. Default: 8765")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        require_admin()
        server = ThreadingHTTPServer((args.host, args.port), WiFindHandler)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not bind to {args.host}:{args.port}. Try another port with --port.", file=sys.stderr)
        print(f"Details: {exc}", file=sys.stderr)
        return 1

    url = f"http://{args.host}:{args.port}"
    print(f"WiFind is running at {url}")
    print("Close this window or press Ctrl+C to stop.")

    if not args.no_browser:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WiFind.")
    finally:
        server.server_close()
    return 0


def open_browser(url: str) -> None:
    time.sleep(1)
    webbrowser.open(url)


if __name__ == "__main__":
    raise SystemExit(main())
