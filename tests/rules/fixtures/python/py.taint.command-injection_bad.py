import os


def view(request):
    os.system("ping -c 1 " + request.args.get("host"))
