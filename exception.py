# define Python user-defined exceptions
class Error(Exception):
    """Base class for other exceptions"""
    pass


class FailedHandshakeError(Error):
    """Raised when the input value is too small"""
    pass
