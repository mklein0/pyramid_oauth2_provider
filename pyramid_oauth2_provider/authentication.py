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

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import (
    AuthTktAuthenticationPolicy,
    CallbackAuthenticationPolicy,
)

from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPUnauthorized,
)

from pyramid_oauth2_provider.errors import (
    InvalidToken,
    InvalidRequest,
)
from pyramid_oauth2_provider.interfaces.model import IOAuth2Model
from pyramid_oauth2_provider.util import get_client_credentials


log = logging.getLogger('pyramid_oauth2_provider.authentication')


@implementer(IAuthenticationPolicy)
class OauthAuthenticationPolicy(CallbackAuthenticationPolicy):

    @staticmethod
    def _is_oauth(request):
        """

        :param pyramid.request.Request request: Incoming Web Request

        :return: True if request has authentication credentals
        :rtype: bool
        """
        return bool(get_client_credentials(request))

    @staticmethod
    def _get_auth_token(request):
        """
        Get access token from request if present and translate it to the access token record.

        :param pyramid.request.Request request: Incoming Web Request

        :return: returns Access Token record for authentiated users, otherwise None for unauthenticated.
        """
        token_type, token = get_client_credentials(request)
        if token_type != 'bearer':
            return None

        model_if = request.registry.queryUtility(IOAuth2Model)()
        auth_token = model_if.lookup_token_access_by_token_id(token)

        # Bad input, return 400 Invalid Request
        if not auth_token:
            raise HTTPBadRequest(InvalidRequest())
        # Expired or revoked token, return 401 invalid token
        if auth_token.is_revoked():
            raise HTTPUnauthorized(InvalidToken())

        return auth_token

    def unauthenticated_userid(self, request):
        """

        :param pyramid.request.Request request: Incoming Web Request

        :return: returns user id for authentiated users, otherwise None for unauthenticated.
        """
        auth_token = self._get_auth_token(request)
        if not auth_token:
            return None

        return auth_token.user_id

    def remember(self, request, principal, **kw):
        """
        I don't think there is anything to do for an oauth access token authorized request here.

        :param pyramid.request.Request request: Incoming Web Request
        :param str principal: Stuff
        :param dict kw: Additional properties to remember as part of the authenticated user.
        """

    def forget(self, request):
        auth_token = self._get_auth_token(request)
        if not auth_token:
            return None

        auth_token.revoke()


@implementer(IAuthenticationPolicy)
class OauthTktAuthenticationPolicy(OauthAuthenticationPolicy,
                                   AuthTktAuthenticationPolicy):
    """
    An Authentication Decoder. Decodes both OAuth2 Access Token Authorization and Pyramid cookie based authentication.
    """
    def __init__(self, *args, **kwargs):
        OauthAuthenticationPolicy.__init__(self)
        AuthTktAuthenticationPolicy.__init__(self, *args, **kwargs)

    def unauthenticated_userid(self, request):
        """

        :param pyramid.request.Request request: Incoming Web Request

        :return: returns user id for authentiated users, otherwise None for unauthenticated.
        """
        if self._is_oauth(request):
            return OauthAuthenticationPolicy.unauthenticated_userid(
                self, request)
        else:
            return AuthTktAuthenticationPolicy.unauthenticated_userid(
                self, request)

    def remember(self, request, principal, **kw):
        """

        :param pyramid.request.Request request: Incoming Web Request
        :param str principal: Stuff
        :param dict kw: Additional properties to remember as part of the authenticated user.
        """
        if self._is_oauth(request):
            return OauthAuthenticationPolicy.remember(
                self, request, principal, **kw)
        else:
            return AuthTktAuthenticationPolicy.remember(
                self, request, principal, **kw)

    def forget(self, request):
        """

        :param pyramid.request.Request request: Incoming Web Request
        """
        if self._is_oauth(request):
            return OauthAuthenticationPolicy.forget(
                self, request)
        else:
            return AuthTktAuthenticationPolicy.forget(
                self, request)
