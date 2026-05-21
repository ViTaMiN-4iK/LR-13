from __future__ import annotations

import argparse
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description="Scale Go SIEM agents for Lab 13 dynamic scaling demo.")
    parser.add_argument("--detectors", type=int, default=3, help="Number of attack-detector replicas.")
    args = parser.parse_args()
    subprocess.run(
        ["docker", "compose", "up", "-d", "--scale", f"attack-detector={args.detectors}"],
        check=True,
    )
    print(f"attack-detector scaled to {args.detectors} replicas")


if __name__ == "__main__":
    main()

