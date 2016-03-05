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

import time
import random
import hashlib


def _get_hash():
    """

    :return: Return a SHA256 hash object with random salt
    :rtype: hashlib.sha256
    """
    sha = hashlib.sha256()
    sha.update(str(random.random()))
    sha.update(str(time.time()))
    return sha


def gen_client_id():
    """
    :return: return a randomly generated hex number based on a sha256 hash
    :rtype: str
    """
    return _get_hash().hexdigest()


def gen_client_secret():
    """
    :return: return a randomly generated hex number based on a sha256 hash
    :rtype: str
    """
    return _get_hash().hexdigest()


def gen_token(client):
    """
    :param client: OAuth2 Client Record

    :return: return a randomly generated hex number based on a sha256 hash and client id
    :rtype: str
    """
    sha = _get_hash()
    sha.update(client.client_id)
    return sha.hexdigest()
