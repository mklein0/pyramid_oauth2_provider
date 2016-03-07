#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
# Copyright (c) 2016 Marcos Klein
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
from pyramid.httpexceptions import HTTPFound

from urlparse import (
    urlparse,
    parse_qsl,
    ParseResult,
)
from urllib import urlencode

from pyramid_oauth2_provider.util import oauth2_settings
from pyramid_oauth2_provider.errors.authorize import (
    InvalidRequest,
    UnsupportedResponseType,
)
from pyramid_oauth2_provider.jsonerrors import HTTPBadRequest
from pyramid_oauth2_provider.interfaces.model import IOAuth2Model
from pyramid_oauth2_provider.views.util import require_https


log = logging.getLogger('pyramid_oauth2_provider.views')


@view_config(
    route_name='oauth2_provider.authorize',
    renderer='json',
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
    model_if = client = None
    request.client_id = request.params.get('client_id')

    if request.client_id:
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
    if response_type in ('code', 'token'):
        return handle_authorize(request, client)

    # Else,
    log.info('received invalid response_type %s', response_type)
    return HTTPBadRequest(UnsupportedResponseType())


def handle_authorize(request, client):
    """
    Setup call to real login URI which will authenticate the user and complete the authorization flow before returning
    to the complete flow end-point.

    :param pyramid.request.Request request:
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Client client: OAuth2 Client Interface

    :rtype: pyramid.httpexceptions.HTTPFound
    """
    # Look up SSL setting and login URI
    settings = oauth2_settings(settings=request.registry.settings)

    # Redirect to login page reiterating oauth2 authorize parameters. They will be returned.
    parts = urlparse(settings['login_uri'])
    qparams = dict(parse_qsl(parts.query))
    qparams['client_id'] = client.client_id
    qparams.update({
        key: request.params[key]
        for key in ('response_type', 'redirect_uri', 'scope', 'state')
        if key in request.params
    })
    if settings.get('require_ssl') == 'false':
        # SSL is not necessarily required, preserve what ever scheme is in use now.
        if parts.scheme == '+':
            # Special scheme to trick urlparse to accept blank schemes.
            scheme = request.scheme

        else:
            scheme = parts.scheme

    else:
        scheme = 'https'

    new_url = ParseResult(
        scheme, parts.netloc or request.host_port, parts.path, parts.params, urlencode(qparams), parts.fragment)
    response = HTTPFound(location=new_url.geturl())

    return response


@view_config(
    route_name='oauth2_provider.authorize.complete',
)
@require_https
def oauth2_authorize_complete(request):
    """

    :param pyramid.request.Request request: Incoming Web Request
    """

    model_if = client = None
    request.client_id = request.params.get('client_id')

    if request.client_id:
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

    user_id = request.authenticated_userid
    if not user_id:
        log.info('User ID not in authentication session')
        raise HTTPBadRequest(InvalidRequest(
            error_description='Invalid client credentials'))

    response_type = request.params.get('response_type')
    scope = request.params.get('scope')
    state = request.params.get('state')

    if response_type == 'token':
        return handle_authorize_complete_implicit(
            request, client, user_id, redirection_uri, model_if, state=state, scope=scope)

    elif response_type == 'code':
        return handle_authorize_complete_authcode(
            request, client, user_id, redirection_uri, model_if,  state=state, scope=scope)

    # Else, Unknown authorization
    return HTTPBadRequest(UnsupportedResponseType())


def handle_authorize_complete_authcode(request, client, user_id, redirection_uri, model_if, state=None, scope=None):
    """
    Setup an authorization code session.

    :param pyramid.request.Request request: Incoming Web Request
    :param pyuserdb.cassandra_.models.OAuth2Client client: OAuth2 Client Record
    :param uuid.UUID user_id: UUID for user
    :param str redirection_uri: redirection URI associated with client
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Model model_if: Data Model Interface
    :param str | None state: optional state string
    :param list[str] | None scope: optional scope strings

    :return:
    """
    auth_code = model_if.create_authorization_code(client, user_id, redirection_uri, scope, state)

    # Decompose redirect uri before putting it back together
    parts = urlparse(redirection_uri or client.redirect_uri)

    # Update the query string parameters if any.
    qparams = dict(parse_qsl(parts.query))
    qparams['code'] = auth_code.authorization_code
    if state:
        qparams['state'] = state

    new_url = ParseResult(parts.scheme, parts.netloc, parts.path, parts.params, urlencode(qparams), parts.fragment)
    return HTTPFound(location=new_url.geturl())


def handle_authorize_complete_implicit(request, client, user_id, redirection_uri, model_if, state=None, scope=None):
    """
    Setup an access token for use by implicit session.

    :param pyramid.request.Request request: Incoming Web Request
    :param pyuserdb.cassandra_.models.OAuth2Client client: OAuth2 Client Record
    :param uuid.UUID user_id: UUID for user
    :param str redirection_uri: redirection URI associated with client
    :param pyramid_oauth2_provider.interfaces.model.OAuth2Model model_if: Data Model Interface
    :param str | None state: optional state string
    :param str | None scope: optional/required scope string
    :param list[str] | None scope: optional scope strings

    :return:
    """
    auth_token = model_if.create_token_access(client, user_id, allow_refresh=False)

    parts = urlparse(redirection_uri)

    # parse_qsl drops any values it does not understand.
    fragments = dict(parse_qsl(parts.fragment))

    fragments.update(auth_token.asJSON(token_type='bearer'))
    if scope:
        fragments['scope'] = scope
    if state:
        fragments['state'] = state

    new_url = ParseResult(parts.scheme, parts.netloc, parts.path, parts.params, parts.query, urlencode(fragments))
    response = HTTPFound(location=new_url.geturl())
    return response
