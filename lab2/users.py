from binascii import hexlify, unhexlify
import csv
from pathlib import Path
from utils import str_to_bool


class Users:
    _users: list[list[str]]

    def __init__(self) -> None:
        self._users = []

    def set_should_change(self, username: str, value: bool) -> None:
        user = list(filter(lambda x: x[0] == username, self._users))[0]
        user[3] = str(value)

        self.remove(username)
        self._users.append(user)

    def add(self, username: str, salt: bytes, hash: bytes, forcepass: bool) -> None:
        self._users.append(
            [
                username,
                hexlify(salt).decode("utf-8"),
                hexlify(hash).decode("utf-8"),
                str(forcepass),
            ]
        )

    def get(self, username: str) -> tuple[bytes, bytes, bool]:
        user = list(filter(lambda x: x[0] == username, self._users))[0]
        return unhexlify(user[1]), unhexlify(user[2]), str_to_bool(user[3])

    def exists(self, username: str) -> bool:
        return len(list(filter(lambda x: x[0] == username, self._users))) > 0

    def remove(self, username: str):
        self._users = list(filter(lambda x: x[0] != username, self._users))

    def read(self, path: str) -> None:
        if not Path(path).exists():
            with open(path, "w"):
                return

        with open(path, "r") as file:
            reader = csv.reader(file)

            for row in reader:
                self._users.append(row)

    def write(self, path: str) -> None:
        with open(path, "w", newline="") as file:
            writer = csv.writer(file)

            for row in self._users:
                writer.writerow(row)
