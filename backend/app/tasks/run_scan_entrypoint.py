"""
Isolated scan container entrypoint — Phase 13.
Called as: python -m app.tasks.run_scan_entrypoint <scan_id>
Runs entirely inside the ephemeral Docker container.
"""
import asyncio
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: run_scan_entrypoint <scan_id>", file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]

    from app.tasks.scan import _run_scan_async
    result = asyncio.run(_run_scan_async(scan_id))
    print(f"completed: {result}")
    sys.exit(0)


if __name__ == "__main__":
    main()
