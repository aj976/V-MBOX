"""VM-only benign process chain; no injection or network egress."""

import subprocess
import sys


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("run only in the isolated Windows VM")
    subprocess.run([sys.executable, "-c", "pass"], check=True)


if __name__ == "__main__":
    main()
