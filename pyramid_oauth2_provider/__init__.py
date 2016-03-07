#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#
from pyramid.config import Configurator
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy

from pyramid_oauth2_provider.interfaces.authentication import IAuthCheck
from pyramid_oauth2_provider.interfaces.model import IOAuth2Model
from pyramid_oauth2_provider.authentication import OauthAuthenticationPolicy
from pyramid_oauth2_provider.util import oauth2_setting


def includeme(config):
    """

    :param pyramid.config.Configurator config: Pyramid WSGI Config Object
    """
    settings = config.registry.settings

    if not config.registry.queryUtility(IAuthenticationPolicy):
        config.set_authentication_policy(OauthAuthenticationPolicy())

    auth_check = settings.get('oauth2_provider.auth_checker')
    if not auth_check:
        raise ConfigurationError(
            'You must provide an implementation of the authentication check interface that is included with '
            'pyramid_oauth2_provider for verifying usernames and passwords'
        )

    policy = config.maybe_dotted(auth_check)
    config.registry.registerUtility(policy, IAuthCheck)

    model_if = settings.get('oauth2_provider.model_interface')
    if not model_if:
        raise ConfigurationError(
            'You must provide an implementation of the model interface that is included with '
            'pyramid_oauth2_provider for accessing the OAuth2 datastore'
        )

    inf = config.maybe_dotted(model_if)
    config.registry.registerUtility(inf, IOAuth2Model)
    inf().configure_app(config)

    login_uri = oauth2_setting('login_uri', default='', settings=settings).strip()
    if not login_uri:
        raise ConfigurationError(
            'You must provide a login URI to which is wrapped by the authorize call.'
        )

    config.add_route('oauth2_provider.authorize', '/oauth2/authorize')
    config.add_route('oauth2_provider.authorize.complete', '/oauth2/authorize/complete')
    config.add_route('oauth2_provider.token', '/oauth2/token')
    config.scan()


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    includeme(config)
    return config.make_wsgi_app()
