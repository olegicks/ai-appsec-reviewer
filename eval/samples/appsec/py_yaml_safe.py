import yaml


def load_recipe(text):
    return yaml.safe_load(text)
