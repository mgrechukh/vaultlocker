# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


class VaultlockerException(Exception):

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = "Empty VaultlockerException"

    def __str__(self):
        return self.message


class VaultWriteError(VaultlockerException):

    def __init__(self, path, error):
        self.path = path
        self.error = error

    def __str__(self):
        return "Can't write to vault at path {},\
             error: {}".format(self.path, self.error)


class VaultReadError(VaultlockerException):

    def __init__(self, path, error):
        self.path = path
        self.error = error

    def __str__(self):
        return "Can't read vault at path {},\
             error: {}".format(self.path, self.error)


class VaultDeleteError(VaultlockerException):

    def __init__(self, path, error):
        self.path = path
        self.error = error

    def __str__(self):
        return "Can't delete vault key at path {},\
             error: {}".format(self.path, self.error)


class VaultKeyMismatch(VaultlockerException):

    def __init__(self, path):
        self.path = path

    def __str__(self):
        return "Vault key at path {} does not match\
             with generated key".format(self.path)


class LUKSFailure(VaultlockerException):

    def __init__(self, block_device, error):
        self.block_device = block_device
        self.error = error

    def __str__(self):
        return "Can't operate on {}.\
             Error: {}".format(self.block_device, self.error)
