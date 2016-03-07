#
# Copyright (c) 2016 Marcos Klein <>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#
from pyramid_oauth2_provider.errors.base import BaseOauth2Error


class InvalidRequest(BaseOauth2Error):
    """
    The request is missing a required parameter, includes an
    invalid parameter value, includes a parameter more than
    once, or is otherwise malformed.

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'invalid_request'


class UnauthorizedClient(BaseOauth2Error):
    """
    The client is not authorized to request an authorization
    code using this method.

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'unauthorized_client'


class AccessDenied(BaseOauth2Error):
    """
    The resource owner or authorization server denied the
    request.

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'access_denied'


class UnsupportedResponseType(BaseOauth2Error):
    """
    The authorization server does not support obtaining an
    authorization code using this method.

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'unsupported_response_type'


class InvalidScope(BaseOauth2Error):
    """
    The requested scope is invalid, unknown, or malformed.

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'invalid_scope'


class ServerError(BaseOauth2Error):
    """
    The authorization server encountered an unexpected
    condition that prevented it from fulfilling the request.
    (This error code is needed because a 500 Internal Server
    Error HTTP status code cannot be returned to the client
    via an HTTP redirect.)

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'server_error'


class TemporarilyUnavailable(BaseOauth2Error):
    """
    The authorization server is currently unable to handle
    the request due to a temporary overloading or maintenance
    of the server.  (This error code is needed because a 503
    Service Unavailable HTTP status code cannot be returned
    to the client via an HTTP redirect.)

    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    """
    error_name = 'temporarily_unavailable'