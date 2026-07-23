import subprocess


def run(cmd: str) -> None:
    subprocess.run(["echo", cmd], check=True)
