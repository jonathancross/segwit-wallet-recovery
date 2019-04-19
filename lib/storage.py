#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading
import json
import copy
import stat
import pbkdf2, hmac, hashlib
import base64
import zlib

from .util import PrintError
from . import bitcoin


# seed_version is now used for the version of the wallet file

FINAL_SEED_VERSION = 16     # electrum >= 2.7 will set this to prevent
                            # old versions from overwriting new format

class WalletStorage(PrintError):

    def __init__(self, path):
        self.lock = threading.RLock()
        self.data = {}
        self.path = path
        self.modified = False
        self.pubkey = None
        if self.file_exists():
            with open(self.path, "r") as f:
                self.raw = f.read()
            if not self.is_encrypted():
                self.load_data(self.raw)
        else:
            # avoid new wallets getting 'upgraded'
            self.put('seed_version', FINAL_SEED_VERSION)


    def is_encrypted(self):
        try:
            return base64.b64decode(self.raw)[0:4] == b'BIE1'
        except:
            return False

    def file_exists(self):
        return self.path and os.path.exists(self.path)

    def get_key(self, password):
        secret = pbkdf2.PBKDF2(password, '', iterations = 1024, macmodule = hmac, digestmodule = hashlib.sha512).read(64)
        ec_key = bitcoin.EC_KEY(secret)
        return ec_key

    def set_password(self, password, encrypt):
        self.put('use_encryption', bool(password))
        if encrypt and password:
            ec_key = self.get_key(password)
            self.pubkey = ec_key.get_public_key()
        else:
            self.pubkey = None

    def get(self, key, default=None):
        with self.lock:
            v = self.data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def put(self, key, value):
        try:
            json.dumps(key)
            json.dumps(value)
        except:
            self.print_error("json error: cannot save", key)
            return
        with self.lock:
            if value is not None:
                if self.data.get(key) != value:
                    self.modified = True
                    self.data[key] = copy.deepcopy(value)
            elif key in self.data:
                self.modified = True
                self.data.pop(key)


    def write(self):
        with self.lock:
            self._write()

    def _write(self):
        if threading.currentThread().isDaemon():
            self.print_error('warning: daemon thread cannot write wallet')
            return
        if not self.modified:
            return
        s = json.dumps(self.data, indent=4, sort_keys=True)
        if self.pubkey:
            s = bytes(s, 'utf8')
            c = zlib.compress(s)
            s = bitcoin.encrypt_message(c, self.pubkey)
            s = s.decode('utf8')

        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w") as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())

        mode = os.stat(self.path).st_mode if os.path.exists(self.path) else stat.S_IREAD | stat.S_IWRITE
        # perform atomic write on POSIX systems
        try:
            os.rename(temp_path, self.path)
        except:
            os.remove(self.path)
            os.rename(temp_path, self.path)
        os.chmod(self.path, mode)
        self.print_error("saved", self.path)
        self.modified = False

