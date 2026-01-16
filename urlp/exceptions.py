class URLpError(Exception):
    """Base exception for URLp errors."""
    pass

class InvalidURLError(URLpError):
    """Exception raised for invalid URLs."""
    pass

class URLParseError(InvalidURLError):
    """Exception raised for errors during URL parsing."""
    pass

class URLBuildError(InvalidURLError):
    """Exception raised for errors during URL building."""
    pass

class UnsupportedSchemeError(InvalidURLError):
    """Exception raised for unsupported URL schemes."""
    pass

class RelativeReferenceError(InvalidURLError):
    """Exception raised for errors in relative URL references."""
    pass

class QuerySerializationError(InvalidURLError):
    """Exception raised for errors during query serialization."""
    pass

class QueryParsingError(InvalidURLError):
    """Exception raised for errors during query parsing."""
    pass

class HostValidationError(InvalidURLError):
    """Exception raised for invalid hostnames."""
    pass

class PortValidationError(InvalidURLError):
    """Exception raised for invalid port numbers."""
    pass

class PathNormalizationError(InvalidURLError):
    """Exception raised for errors during path normalization."""
    pass

class FragmentEncodingError(InvalidURLError):
    """Exception raised for errors during fragment encoding."""
    pass

class NetlocBuildingError(InvalidURLError):
    """Exception raised for errors during netloc building."""
    pass

class UserInfoParsingError(InvalidURLError):
    """Exception raised for errors during userinfo parsing."""
    pass

class MissingHostError(InvalidURLError):
    """Exception raised when a required host is missing."""
    pass

class MissingPortError(InvalidURLError):
    """Exception raised when a required port is missing."""
    pass
