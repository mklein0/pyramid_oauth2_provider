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

from pyramid.view import view_config
from pyramid.security import (
    authenticated_userid,
    Authenticated,
)
from pyramid.httpexceptions import HTTPFound

from urlparse import (
    urlparse,
    parse_qsl,
    ParseResult,
)
from urllib import urlencode

from pyramid_oauth2_provider.errors import InvalidRequest
from pyramid_oauth2_provider.jsonerrors import HTTPBadRequest
from pyramid_oauth2_provider.interfaces.model import IOAuth2Model
from pyramid_oauth2_provider.views.util import require_https


log = logging.getLogger('pyramid_oauth2_provider.views')


@view_config(
    route_name='oauth2_provider.authorize',
    renderer='json',
    permission=Authenticated,
)
@require_https
def oauth2_authorize(request):
    """
    * In the case of a 'code' authorize request a GET or POST is made
    with the following structure.

        GET /authorize?response_type=code&client_id=aoiuer HTTP/1.1
        Host: server.example.com

        POST /authorize HTTP/1.1
        Host: server.example.com
        Content-Type: application/x-www-form-urlencoded

        response_type=code&client_id=aoiuer

    The response_type and client_id are required parameters. A redirect_uri
    and state parameters may also be supplied. The redirect_uri will be
    validated against the URI's registered for the client. The state is an
    opaque value that is simply passed through for security on the client's
    end.

    The response to a 'code' request will be a redirect to a registered URI
    with the authorization code and optional state values as query
    parameters.

        HTTP/1.1 302 Found
        Location: https://client.example.com/cb?code=AverTaer&state=efg


    :param pyramid.request.Request request: Incoming Web Request
    """
    request.client_id = request.params.get('client_id')

    model_if = request.registry.queryUtility(IOAuth2Model)()
    client = model_if.lookup_client_by_client_id(request.client_id)

    if not client:
        log.info('received invalid client credentials')
        return HTTPBadRequest(InvalidRequest(
            error_description='Invalid client credentials'))

    redirect_uri = request.params.get('redirect_uri')
    redirection_uri = client.lookup_redirect_uri(redirect_uri)

    if redirection_uri is None:
        return HTTPBadRequest(InvalidRequest(
            error_description='Redirection URI validation failed'))

    response_type = request.params.get('response_type')
    state = request.params.get('state')
    if 'code' == response_type:
        resp = handle_authcode(request, client, redirection_uri, model_if, state)
    elif 'token' == response_type:
        resp = handle_implicit(request, client, redirection_uri, model_if, state)
    else:
        log.info('received invalid response_type %s')
        resp = HTTPBadRequest(InvalidRequest(error_description='Oauth2 unknown response_type not supported'))
    return resp


def handle_authcode(request, client, redirection_uri, model_if, state=None):
    """

    :param pyramid.request.Request request:
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Client client: OAuth2 Client Interface
    :param str redirection_uri: Redirection URI
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Model model_if: Data Model Interface
    :param str state: Optional state to return to client on redirect

    :return:
    """
    parts = urlparse(redirection_uri)
    qparams = dict(parse_qsl(parts.query))

    user_id = authenticated_userid(request)
    auth_code = model_if.create_authorization_code(client, user_id)

    qparams['code'] = auth_code.authorization_code
    if state:
        qparams['state'] = state
    parts = ParseResult(
        parts.scheme, parts.netloc, parts.path, parts.params,
        urlencode(qparams), '')
    return HTTPFound(location=parts.geturl())


def handle_implicit(request, client, redirection_uri, model_if, state=None):
    """
    :param pyramid.request.Request request:
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Client client: OAuth2 Client Interface
    :param str redirection_uri: Redirection URI
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Model model_if: Data Model Interface
    :param str state: Optional state to return to client on redirect

    :return:
    """
    return HTTPBadRequest(InvalidRequest(error_description='Oauth2 '
        'response_type "implicit" not supported'))