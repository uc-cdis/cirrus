from cirrus.errors import CirrusError


class GoogleNamingError(CirrusError):
    def __init__(
        self,
        message=(
            "There was an issue with generating names or ids that are compliant "
            "with Google's requirements."
        ),
    ):
        super(GoogleNamingError, self).__init__(message)


class GoogleAuthError(CirrusError):
    def __init__(self,):
        super(GoogleAuthError, self).__init__(
            "This action requires an authed session. Please use "
            "Python's `with <Class> as <name>` syntax for a context manager "
            "that automatically enters and exits authorized sessions using "
            "default credentials. See cirrus's README for setup instructions."
        )


class GoogleAPIError(CirrusError):
    def __init__(self, message="There was an issue with requesting Google API"):
        super(GoogleAPIError, self).__init__(message)
