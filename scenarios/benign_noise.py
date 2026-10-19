"""VM-only benign process and loopback network workload for M1."""

import argparse
import socket
import subprocess
import sys
import threading
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("run only in the isolated Windows VM")
    if args.duration <= 0 or args.interval <= 0:
        parser.error("duration and interval must be positive")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    end = time.monotonic() + args.duration

    def serve() -> None:
        while time.monotonic() < end:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                conn.recv(1)

    thread = threading.Thread(target=serve)
    thread.start()
    iterations = 0
    try:
        while time.monotonic() < end:
            subprocess.run([sys.executable, "-c", "pass"], check=True)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.sendall(b"x")
            iterations += 1
            time.sleep(args.interval)
    finally:
        thread.join()
        listener.close()
    print(f"completed_process_and_loopback_iterations: {iterations}")


if __name__ == "__main__":
    main()
