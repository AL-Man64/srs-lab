class PasswordMismatchError(Exception):
    pass


class DuplicateUserError(Exception):
    pass


class NonExistentUserError(Exception):
    pass


class IncorrectPasswordError(Exception):
    pass


class PasswordTooShortError(Exception):
    pass
