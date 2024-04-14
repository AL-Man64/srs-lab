#!/usr/bin/env ./venv/bin/python3


from Crypto.Protocol.KDF import bcrypt
import argparse
import sys
from getpass import getpass
from secrets import token_bytes

from error import (
    DuplicateUserError,
    NonExistentUserError,
    PasswordMismatchError,
    PasswordTooShortError,
)
from utils import users_path
from users import Users
from constants import BCRYPT_COST


def main() -> None:
    parser = argparse.ArgumentParser(description="User management tool")

    parser.add_argument(
        "subcommand",
        choices=["add", "passwd", "forcepass", "del"],
        help="Subcommand to execute",
    )
    parser.add_argument("username", type=str, help="Username to perform the action on")

    args = parser.parse_args()

    users: Users = Users()
    users.read(users_path)

    try:
        if args.subcommand == "add":
            cmd_add(args.username, users)
        elif args.subcommand == "passwd":
            cmd_passwd(args.username, users)
        elif args.subcommand == "forcepass":
            cmd_forcepass(args.username, users)
        elif args.subcommand == "del":
            cmd_del(args.username, users)
        else:
            parser.print_help()

    except PasswordMismatchError:
        print("Error: password mismatch", file=sys.stderr)

    except DuplicateUserError:
        print("Error: user already exists", file=sys.stderr)

    except NonExistentUserError:
        print("Error: user does not exist", file=sys.stderr)

    except PasswordTooShortError:
        print("Password must be at least 8 characters long", file=sys.stderr)


def cmd_add(username: str, users: Users) -> None:
    if users.exists(username):
        raise DuplicateUserError()

    password: str = getpass("Password: ")
    if len(password) < 8:
        raise PasswordTooShortError

    repeat_password: str = getpass("Repeat Password: ")

    if password != repeat_password:
        raise PasswordMismatchError()

    salt = token_bytes(16)
    password_hash = bcrypt(password, cost=BCRYPT_COST, salt=salt)

    users.add(username, salt, password_hash, False)

    users.write(users_path)

    print(f"User {username} successfully added")


def cmd_passwd(username: str, users: Users) -> None:
    if not users.exists(username):
        raise NonExistentUserError()

    password: str = getpass("Password: ")
    if len(password) < 8:
        raise PasswordTooShortError

    repeat_password: str = getpass("Repeat Password: ")

    if password != repeat_password:
        raise PasswordMismatchError()

    salt = token_bytes(16)
    password_hash = bcrypt(password, cost=BCRYPT_COST, salt=salt)

    users.remove(username)
    users.add(username, salt, password_hash, False)

    users.write(users_path)

    print("Password change successful.")


def cmd_forcepass(username: str, users: Users) -> None:
    if not users.exists(username):
        raise NonExistentUserError()

    users.set_should_change(username, True)

    users.write(users_path)

    print("User will be requested to change password on next login.")


def cmd_del(username: str, users: Users) -> None:
    if not users.exists(username):
        raise NonExistentUserError()

    users.remove(username)

    users.write(users_path)

    print("User successfully removed.")


if __name__ == "__main__":
    main()
