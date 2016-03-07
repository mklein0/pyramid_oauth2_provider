#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
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
    unsupported parameter value (other than grant type),
    repeats a parameter, includes multiple credentials,
    utilizes more than one mechanism for authenticating the
    client, or is otherwise malformed.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'invalid_request'


class InvalidClient(BaseOauth2Error):
    """
    Client authentication failed (e.g., unknown client, no
    client authentication included, or unsupported
    authentication method).  The authorization server MAY
    return an HTTP 401 (Unauthorized) status code to indicate
    which HTTP authentication schemes are supported.  If the
    client attempted to authenticate via the "Authorization"
    request header field, the authorization server MUST
    respond with an HTTP 401 (Unauthorized) status code and
    include the "WWW-Authenticate" response header field
    matching the authentication scheme used by the client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'invalid_client'


class InvalidGrant(BaseOauth2Error):
    """
    The provided authorization grant (e.g., authorization
    code, resource owner credentials) or refresh token is
    invalid, expired, revoked, does not match the redirection
    URI used in the authorization request, or was issued to
    another client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'invalid_grant'


class UnauthorizedClient(BaseOauth2Error):
    """
    The authenticated client is not authorized to use this
    authorization grant type.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'unauthorized_client'


class UnsupportedGrantType(BaseOauth2Error):
    """
    The authorization grant type is not supported by the
    authorization server.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'unsupported_grant_type'


class InvalidScope(BaseOauth2Error):
    """
    The requested scope is invalid, unknown, malformed, or
    exceeds the scope granted by the resource owner.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'invalid_scope'