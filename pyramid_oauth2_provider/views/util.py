#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warranty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#
import logging

from pyramid_oauth2_provider.jsonerrors import HTTPBadRequest
from pyramid_oauth2_provider.errors import InvalidRequest
from pyramid_oauth2_provider.util import oauth2_settings


log = logging.getLogger('pyramid_oauth2_provider.views')


def require_https(handler):
    """
     This check should be taken care of via the authorization policy, but in
     case someone has configured a different policy, check again. HTTPS is
     required for all Oauth2 authenticated requests to ensure the security of
     client credentials and authorization tokens.

     :param callable handler: Function to wrap

    """
    def wrapped(request):
        """

        :param pyramid request.Request request: Incoming Web Request
        """
        if (request.scheme != 'https' and
                oauth2_settings('require_ssl', default=True)):
            log.info('rejected request due to unsupported scheme: %s'
                     % request.scheme)
            return HTTPBadRequest(InvalidRequest(
                error_description='Oauth2 requires all requests'
                                  ' to be made via HTTPS.'))
        return handler(request)
    return wrapped


def add_cache_headers(request):
    """
    The Oauth2 draft spec requires that all token endpoint traffic be marked
    as uncacheable.

    :param pyramid.request.Request request: Incoming Web Request

    :rtype: pyramid.request.Request
    """

    resp = request.response
    resp.headerlist.append(('Cache-Control', 'no-store'))
    resp.headerlist.append(('Pragma', 'no-cache'))
    return request
