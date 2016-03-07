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


class BaseOauth2Error(dict):
    error_name = None

    def __init__(self, **kw):
        super(BaseOauth2Error, self).__init__()
        if kw:
            self.update(kw)
        self['error'] = self.error_name

        if 'error_description' not in self:
            self['error_description'] = self.__doc__