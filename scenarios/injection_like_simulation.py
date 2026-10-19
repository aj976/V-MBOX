"""VM-only benign sequence: child process, query-only handle, loopback connection.

No code injection, remote thread, memory write, malware, or network egress.
Unverified until run on Windows VM; Sysmon 10 may or may not report the query.
"""

import argparse
import ctypes
import socket
import subprocess
import sys
import threading
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=10)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("run only in the isolated Windows VM")
    if args.duration <= 0:
        parser.error("duration must be positive")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    def serve() -> None:
        with listener:
            listener.settimeout(5)
            conn, _ = listener.accept()
            with conn:
                conn.recv(1)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x1000, 0, child.pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle(handle)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(b"x")
        time.sleep(args.duration)
    finally:
        child.terminate()
        child.wait(timeout=5)
        thread.join()


if __name__ == "__main__":
    main()
