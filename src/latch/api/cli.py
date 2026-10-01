"""Command-line launcher for the local browser demo."""

from __future__ import annotations

import argparse

import uvicorn

from latch.api.app import create_app

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Latch hackathon demo.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow binding the demo server to a non-loopback interface.",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.host not in _LOOPBACK_HOSTS and not args.allow_network:
        parser.error(
            "refusing non-loopback bind without --allow-network; "
            "the demo control plane is local-only by default"
        )

    uvicorn.run(
        create_app(),
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
