import os


users_path: str

if os.name == "nt":
    users_path = os.environ.get("USERPROFILE") + "\\users.csv"
else:
    users_path = os.path.expanduser("~/users.csv")


def str_to_bool(s):
    return s == "True"
