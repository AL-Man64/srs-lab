#!/usr/bin/env ./venv/bin/python3


import subprocess
import sys
import argparse
from getpass import getpass
from Crypto.Protocol.KDF import bcrypt
from secrets import token_bytes

from constants import BCRYPT_COST
from error import (
    PasswordMismatchError,
    IncorrectPasswordError,
    NonExistentUserError,
    PasswordTooShortError,
)
from utils import users_path
from users import Users


def main():
    parser = argparse.ArgumentParser(description="Log in to the shell")
    parser.add_argument("username", type=str, help="Login username")

    args = parser.parse_args()

    try:
        login(args.username)

    except NonExistentUserError:
        print("Error: user does not exist", file=sys.stderr)

    except PasswordMismatchError:
        print("Error: password mismatch", file=sys.stderr)

    except IncorrectPasswordError:
        print("User entered wrong password 3 times", file=sys.stderr)

    except PasswordTooShortError:
        print("Password must be at least 8 characters long", file=sys.stderr)


def login(username: str):
    users: Users = Users()

    users.read(users_path)
    if not users.exists(username):
        raise NonExistentUserError()

    salt, expected_hash, forcepass = users.get(username)

    for i in range(0, 3):
        password = getpass("Password: ")
        actual_hash = bcrypt(password, cost=BCRYPT_COST, salt=salt)
        if actual_hash == expected_hash:
            break

        print("Username or password incorrect")

        if i == 2:
            raise IncorrectPasswordError()

    if forcepass is True:
        password = getpass("New password: ")
        if len(password) < 8:
            raise PasswordTooShortError

        repeat_password = getpass("Repeat new password: ")

        if password != repeat_password:
            raise PasswordMismatchError()

        salt = token_bytes(16)
        new_hash = bcrypt(password, cost=12, salt=salt)

        users.remove(username)
        users.add(username, salt, new_hash, False)

        users.write(users_path)

    _ = subprocess.run(["bash"], env={"LV_USER": username})


if __name__ == "__main__":
    main()
