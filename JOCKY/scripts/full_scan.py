import subprocess
import sys


COMMANDS = [
    ["jocky", "system-info"],
    ["jocky", "processes"],
    ["jocky", "network"],
    ["jocky", "files", "scripts"],
    ["jocky", "persistence"],
    ["jocky", "evidence"],
    ["jocky", "report"],
]


def run_command(command):
    print("")
    print("=" * 60)
    print("RUNNING:", " ".join(command))
    print("=" * 60)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode


def main():
    print("=" * 60)
    print("          JOCKY FULL FORENSIC SCAN")
    print("=" * 60)

    failed = []

    for command in COMMANDS:
        return_code = run_command(command)

        if return_code != 0:
            failed.append(command)

    print("")
    print("=" * 60)
    print("          JOCKY SCAN COMPLETED")
    print("=" * 60)

    if failed:
        print("")
        print("Failed commands:")

        for command in failed:
            print(" -", " ".join(command))
    else:
        print("")
        print("All scan commands completed successfully.")

    print("")
    print("Evidence directory : evidence/")
    print("Report directory   : reports/")


if __name__ == "__main__":
    main()