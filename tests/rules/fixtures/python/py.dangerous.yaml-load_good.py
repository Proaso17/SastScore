import yaml


def load(data: str) -> object:
    return yaml.load(data, Loader=yaml.SafeLoader)
