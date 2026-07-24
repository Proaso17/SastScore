import jsonpickle


def load(data: str) -> object:
    return jsonpickle.decode(data)
