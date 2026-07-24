import subprocess


def view(request):
    subprocess.run(["ping", "-c", "1", request.args.get("host")], check=True)
