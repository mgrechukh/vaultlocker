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

import base64
import logging
import os
import subprocess
import re

logger = logging.getLogger(__name__)


KEY_SIZE = 4096


def generate_key():
    """Generate a 4096 bit random key for use with dm-crypt

    :returns: str.  Base64 encoded 4096 bit key
    """
    data = os.urandom(int(KEY_SIZE / 8))
    key = base64.b64encode(data).decode('utf-8')
    return key


def luks_status(uuid):
    logger.info('checking status {}'.format(uuid))
    command = [
        'cryptsetup',
        'status',
        'crypt-{}'.format(uuid),
    ]
    subprocess.check_call(command)


def luks_close(uuid):
    logger.info('LUKS disabling {}'.format(uuid))
    command = [
        'cryptsetup',
        'close',
        'crypt-{}'.format(uuid),
    ]
    subprocess.check_output(command)


def luks_check(device):
    """LUKS check if header present

    Check if LUKS present on block device and return uuid if so

    :param: device: full path to block device to use.
    """
    logger.info('LUKS checking {}'.format(device))
    command = [
        'cryptsetup',
        'luksDump',
        device,
    ]

    output = subprocess.check_output(command).decode('UTF-8', 'replace')
    return re.search('^UUID:[ \t]+(?P<uuid>[a-z0-9-]+)$', output, flags=re.MULTILINE).group('uuid')


def luks_format(key, device, uuid):
    """LUKS format a block device

    Format a block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: device: full path to block device to use.
    :param: uuid: uuid to use for encrypted block device.
    """
    logger.info('LUKS formatting {} using UUID:{}'.format(device, uuid))
    command = [
        'cryptsetup',
        '--batch-mode',
        '--uuid',
        uuid,
        '--key-file',
        '-',
        'luksFormat',
        device,
    ]
    subprocess.check_output(command,
                            input=key.encode('UTF-8'))


def luks_open(key, uuid):
    """LUKS open a block device by UUID

    Open a block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :returns: str. dm-crypt mapping
    """
    logger.info('LUKS opening {}'.format(uuid))
    handle = 'crypt-{}'.format(uuid)
    command = [
        'cryptsetup',
        '--batch-mode',
        '--key-file',
        '-',
        'open',
        'UUID={}'.format(uuid),
        handle,
        '--type',
        'luks',
    ]
    subprocess.check_output(command,
                            input=key.encode('UTF-8'))
    return handle


def luks_try_open(key, uuid, slot=None):
    """LUKS validate key is usable

    Validate provided key (passprase) on a block device specified by uuid, using dm-crypt/LUKS

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :param: slot: optionally check passphrase in specific slot only
    """
    logger.info('LUKS testing open {} slot={}'.format(uuid, slot))
    command = [
        'cryptsetup',
        '--batch-mode',
        '--test-passphrase',
        '--key-file',
        '-',
        'open',
        'UUID={}'.format(uuid),
        '--type',
        'luks',
    ]
    if slot != None:
        command.append('--key-slot={}'.format(slot))
    return subprocess.check_output(command,
                                   input=key.encode('UTF-8'))


def luks_add_key(key, uuid, new_key, slot):
    """LUKS add new key to blockdevice

    Add new key to specific slot of block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :param: new_key: string containing the new encryption key to use.
    :param: slot: which slot to put the new key in
    """
    logger.info('LUKS updating passphrase {} on slot {}'.format(uuid, slot))
    keys = (key.encode('UTF-8'), new_key.encode('UTF-8'))
    command = [
        'cryptsetup',
        '--batch-mode',
        '-v',
        '--key-file',
        '-',
        '--key-slot={}'.format(slot),
        '--keyfile-size={}'.format(len(keys[0])),
        '--new-keyfile-offset=1',
        '--new-keyfile-size={}'.format(len(keys[1])),
        'luksAddKey',
        'UUID={}'.format(uuid),
    ]
    return subprocess.check_output(command,
                                   input=b'\n'.join(keys))


def luks_kill_slot(key, uuid, slot):
    """LUKS remove a passphrase by slot number

    Remove passphrase from specific slot on dm-crypt/luks block device 

    Existing key from _another_ slot provded to validate slot removal. This way we
    assure that the provided key remains valid after operation.

    Although cryptsetup itself does not strictly require key - _when_ no key specified it will blindly
    do what asked, which considered dangerous. 

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :param: slot: which slot to remove
    """

    logger.info('LUKS removing on {} key slot {}'.format(uuid, slot))
    command = [
        'cryptsetup',
        '--batch-mode',
        '-v',
        '--key-file',
        '-',
        'luksKillSlot',
        'UUID={}'.format(uuid),
        str(slot),
    ]

    return subprocess.check_output(command,
                                   input=key.encode('UTF-8'))


def udevadm_rescan(device):
    """udevadm trigger for block device addition

    Rescan for block devices to ensure that by-uuid devices are
    created before use.

    :param: device: full path to block device to use.
    """
    logger.info('udevadm trigger block/add for {}'.format(device))
    command = [
        'udevadm',
        'trigger',
        '--name-match={}'.format(device),
        '--action=add'
    ]
    subprocess.check_output(command)


def udevadm_settle(uuid):
    """udevadm settle the newly created encrypted device

    Ensure udev has created the by-uuid symlink for newly
    created encyprted device.

    :param: uuid: uuid to use for encrypted block device.
    """
    logger.info('udevadm settle /dev/disk/by-uuid/{}'.format(uuid))
    command = [
        'udevadm',
        'settle',
        '--exit-if-exists=/dev/disk/by-uuid/{}'.format(uuid),
    ]
    subprocess.check_output(command)
