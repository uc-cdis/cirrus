

class GoogleNamingError(Exception):

    GOOGLE_ERROR_MESSAGE = (
        "There was an issue with generating names or ids that are compliant "
        "with Google's requirements."
    )

    def __init__(self, message=None, *args):
        if not message:
            message = GoogleAuthError.GOOGLE_ERROR_MESSAGE

        super(GoogleNamingError, self).__init__(message)


class GoogleAuthError(Exception):

    GOOGLE_AUTH_ERROR_MESSAGE = (
        "This action requires an authed session. Please use "
        "Python's `with <Class> as <name>` syntax for a context manager "
        "that automatically enters and exits authorized sessions using "
        "default credentials. See cirrus's README for setup instructions."
    )

    def __init__(self, message=None, *args):
        if not message:
            message = GoogleAuthError.GOOGLE_AUTH_ERROR_MESSAGE

        super(GoogleAuthError, self).__init__(message)


class GoogleAPIError(Exception):

    GOOGLE_API_ERROR_MESSAGE = (
        "There was an issue with requesting Google API "
    )

    def __init__(self, message=None, *args):
        if not message:
            message = GoogleAPIError.GOOGLE_API_ERROR_MESSAGE

        super(GoogleAPIError, self).__init__(message)
