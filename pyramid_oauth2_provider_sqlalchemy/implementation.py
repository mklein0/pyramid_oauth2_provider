#
from zope.interface import implementer, directlyProvides

from sqlalchemy import engine_from_config

from pyramid_oauth2_provider_sqlalchemy.models import (
    initialize_sql,
    DBSession as db,
    Oauth2Token,
    Oauth2Code,
    Oauth2Client,
)
from pyramid_oauth2_provider.interfaces.model import (
    IOAuth2Model,
    IOAuth2ModelClient,
)

# Instrument DB Records to provide following interfaces
directlyProvides(Oauth2Client, IOAuth2ModelClient)


@implementer(IOAuth2Model)
class OAuth2ModelInterface(object):

    def lookup_client_by_client_id(self, client_id):
        """
        Lookup the OAuth2 Client based on the client ID provided. Return a interface to the model or None if not found.

        :param str client_id: Client ID to Lookup

        :rtype: IOAuth2ModelClient
        """
        client = db.query(Oauth2Client).filter_by(client_id=client_id).first()

        return client

    def lookup_token_refresh_by_token_id(self, token_id):
        """
        Lookup the OAuth2 Refresh Token based on the refresh token ID provided. Return a interface to the model or
        None if not found.

        :param str token_id: Refresh token ID to Lookup

        :rtype: IOAuth2ModelTokenRefresh
        """
        auth_token = db.query(Oauth2Token).filter_by(refresh_token=token_id).first()
        return auth_token

    def lookup_token_access_by_token_id(self, token_id):
        """
        Lookup the OAuth2 Access Token based on the access token ID provided. Return a interface to the model or
        None if not found.

        :param str token_id: Access token ID to Lookup

        :rtype: IOAuth2ModelTokenAccess
        """
        auth_token = db.query(Oauth2Token).filter_by(access_token=token_id).first()
        return auth_token

    def create_token_access(self, client, user_id, allow_refresh=False):
        """

        :param Oauth2Client client:
        :param user_id:
        :param bool allow_refresh:

        :rtype: IOAuth2ModelToken
        """
        auth_token = Oauth2Token(client, user_id)
        db.add(auth_token)
        db.flush()

        return auth_token

    def refresh_token_access(self, token):
        """
        :param Oauth2Token token:
        """
        new_token = token.refresh()
        db.add(new_token)
        db.flush()

        return new_token

    def create_authorization_code(self, client, user_id, redirection_uri, scope, state):
        """

        :param IOAuth2ModelClient client:
        :param user_id:
        :param redirection_uri:
        :param scope:
        :param state:

        :rtype: IOAuth2ModelCodeAuthorization
        """
        auth_code = Oauth2Code(client, user_id)
        db.add(auth_code)
        db.flush()

        return auth_code

    def configure_app(self, config):
        """

        :param pyramid.config.Configurator config: Pyramid WSGI Config Object
        :return:
        """
        settings = config.registry.settings

        engine = engine_from_config(settings, 'sqlalchemy.')
        initialize_sql(engine, settings)
