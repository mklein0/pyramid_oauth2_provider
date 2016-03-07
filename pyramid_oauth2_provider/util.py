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

import base64
import logging

from pyramid.threadlocal import get_current_registry


log = logging.getLogger('pyramid_oauth2_provider.util')


SETTING_PREFIX = 'oauth2_provider.'
SETTING_FORMAT = SETTING_PREFIX + '{0}'


def oauth2_setting(key, default=None, settings=None):
    """
    This function returns a single key/value within the current pyramid registries settings.

    :param str key: key name
    :param default: default value to return
    :param pyramid.config.settings.Settings settings: Pyramid Application Settings

    :return: Value of key found, or default value given.
    """
    if settings is None:
        settings = get_current_registry().settings

    value = settings.get(SETTING_FORMAT.format(key), default)
    if value == 'true':
        return True
    elif value == 'false':
        return False
    else:
        return value


def oauth2_settings(settings=None):
    """
    This function returns a dict of only oauth2_provider key/values.

    :param pyramid.config.settings.Settings settings: Pyramid Application Settings

    :return: dict of oauth2_provider key/values
    :rtype: dict
    """
    if settings is None:
        settings = get_current_registry().settings

    return dict(
        (x.split('.', 1)[1], y)
        for x, y in settings.iteritems()
        if x.startswith(SETTING_PREFIX)
    )


def get_client_credentials(request):
    """

    :param pyramid.request.Request request: Incoming Request
    :return: Authorization type and authorization token base64 decoded
    :rtype: (str, str) | False
    """
    if 'Authorization' in request.headers:
        auth = request.headers.get('Authorization')
    elif 'authorization' in request.headers:
        auth = request.headers.get('authorization')
    else:
        log.debug('no authorization header found')
        return False

    if (not auth.lower().startswith('bearer') and
            not auth.lower().startswith('basic')):
        log.debug('authorization header not of type bearer or basic: {0}'.format(auth.lower()))
        return False

    parts = auth.split()
    if len(parts) != 2:
        return False

    token_type = parts[0].lower()
    token = base64.b64decode(parts[1])

    if token_type == 'basic':
        client_id, client_secret = token.split(':')
        request.client_id = client_id
        request.client_secret = client_secret

    return token_type, token
