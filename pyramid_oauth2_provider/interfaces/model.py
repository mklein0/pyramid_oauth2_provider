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

from zope.interface import Interface, Attribute


class IOAuth2ModelClient(Interface):

    client_id = Attribute("""
        Client ID
        """)

    client_secret = Attribute("""
        Client Secret
        """)

    def lookup_redirect_uri(self, redirect_uri):
        """

        :param str redirect_uri:

        :return:
        """

    def is_revoked(self):
        """

        :return: True if client is no longer valid, else False
        """

    def save(self, **kwargs):
        """
        Save given record to data store

        :param dict kwargs: Extra parameters the driver implementation may require
        """


class IOAuth2ModelCodeAuthorization(Interface):

    authcode = Attribute("""
        Refresh token ID
        """)

    def save(self, **kwargs):
        """
        Save given record to data store

        :param dict kwargs: Extra parameters the driver implementation may require
        """


class IOAuth2ModelTokenRefresh(Interface):

    refresh_token = Attribute("""
        Refresh token ID
        """)

    def refresh(self, **kwargs):
        """
        Refresh the given associated access token

        :param dict kwargs: Extra parameters the driver implementation may require
        """

    def save(self, **kwargs):
        """
        Save given record to data store

        :param dict kwargs: Extra parameters the driver implementation may require
        """

    def is_revoked(self):
        """

        :return: True if token is no longer valid, else False
        """


class IOAuth2ModelTokenAccess(Interface):

    access_token = Attribute("""
        Access token ID
        """)

    def refresh(self, **kwargs):
        """
        Refresh the given associated access token

        :param dict kwargs: Extra parameters the driver implementation may require
        """

    def save(self, **kwargs):
        """
        Save given record to data store

        :param dict kwargs: Extra parameters the driver implementation may require
        """

    def is_revoked(self):
        """

        :return: True if token is no longer valid, else False
        """


class IOAuth2Model(Interface):
    """
    This interface is for verifying oauth2 information with your
    backing store of choice.
    """

    def lookup_client_by_client_id(self, client_id):
        """
        Lookup the OAuth2 Client based on the client ID provided. Return a interface to the model or None if not found.

        :param str client_id: Client ID to Lookup

        :rtype: IOAuth2ModelClient
        """

    def lookup_token_refresh_by_token_id(self, token_id):
        """
        Lookup the OAuth2 Refresh Token based on the refresh token ID provided. Return a interface to the model or
        None if not found.

        :param str token_id: Refresh token ID to Lookup

        :rtype: IOAuth2ModelTokenRefresh
        """

    def lookup_token_access_by_token_id(self, token_id):
        """
        Lookup the OAuth2 Access Token based on the access token ID provided. Return a interface to the model or
        None if not found.

        :param str token_id: Access token ID to Lookup

        :rtype: IOAuth2ModelTokenAccess
        """

    def create_token_access(self, client, user_id, allow_refresh=False):
        """

        :param IOAuth2ModelClient client:
        :param user_id:
        :param bool allow_refresh:

        :rtype: IOAuth2ModelTokenRefresh
        """

    def create_authorization_code(self, client, user_id):
        """

        :param IOAuth2ModelClient client:
        :param user_id:

        :rtype: IOAuth2ModelCodeAuthorization
        """

    def configure_app(self, config):
        """

        :param pyramid.config.Configurator config: Pyramid WSGI Config Object
        :return:
        """