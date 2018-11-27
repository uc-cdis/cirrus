class CirrusError(BaseException):
    def __init__(self, message="There was an error within the cirrus library.", *args):
        super(CirrusError, self).__init__(message)


class CirrusNotFound(CirrusError):
    def __init__(self, message="Not Found", *args):
        super(CirrusNotFound, self).__init__(message)


class CirrusAttributeError(CirrusError):
    def __init__(self, message="Attribute Error", *args):
        super(CirrusAttributeError, self).__init__(message)
