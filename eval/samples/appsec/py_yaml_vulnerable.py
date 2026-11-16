import yaml


def load_recipe(text):
    return yaml.load(text, Loader=yaml.Loader)
