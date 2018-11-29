class CirrusError(Exception):
    def __init__(self, message="There was an error within the cirrus library.", *args):
        super(CirrusError, self).__init__(message)


class CirrusNotFound(CirrusError):
    def __init__(self, message="Not Found", *args):
        super(CirrusNotFound, self).__init__(message)


class CirrusUserError(CirrusError):
    """
    For invalid calls to the library or malformated input, e.g. an error by the user
    of the library
    """

    def __init__(self, message="User Error", *args):
        super(CirrusNotFound, self).__init__(message)
