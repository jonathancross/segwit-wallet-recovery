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

# Wallet classes:
#   - Imported_Wallet: imported address, no keystore
#   - Standard_Wallet: one keystore, P2PKH
#   - Multisig_Wallet: several keystores, P2SH


import os
import threading
import json
import copy

from .util import PrintError

from .bitcoin import *
from .keystore import load_keystore

from . import bitcoin

class Abstract_Wallet(PrintError):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """


    def __init__(self, storage):
        self.storage = storage
        self.network = None

        self.gap_limit_for_change = 6 # constant
        # saved fields
        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        self.load_keystore()
        self.load_addresses()
        self.load_transactions()
        self.build_reverse_history()

        self.lock = threading.Lock()
        self.transaction_lock = threading.Lock()

        self.check_history()

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        return None


    def load_transactions(self):
        self.txi = self.storage.get('txi', {})
        self.txo = self.storage.get('txo', {})
        self.tx_fees = self.storage.get('tx_fees', {})
        self.pruned_txo = self.storage.get('pruned_txo', {})
        tx_list = self.storage.get('transactions', {})
        self.transactions = {}
        for tx_hash, raw in tx_list.items():
            tx = Transaction(raw)
            self.transactions[tx_hash] = tx
            if self.txi.get(tx_hash) is None and self.txo.get(tx_hash) is None and (tx_hash not in self.pruned_txo.values()):
                self.print_error("removing unreferenced tx", tx_hash)
                self.transactions.pop(tx_hash)


    def save_transactions(self, write=False):
        with self.transaction_lock:
            tx = {}
            for k,v in self.transactions.items():
                tx[k] = str(v)
            self.storage.put('transactions', tx)
            self.storage.put('txi', self.txi)
            self.storage.put('txo', self.txo)
            self.storage.put('tx_fees', self.tx_fees)
            self.storage.put('pruned_txo', self.pruned_txo)
            self.storage.put('addr_history', self.history)
            if write:
                self.storage.write()



    def build_reverse_history(self):
        self.tx_addr_hist = {}
        for addr, hist in self.history.items():
            for tx_hash, h in hist:
                s = self.tx_addr_hist.get(tx_hash, set())
                s.add(addr)
                self.tx_addr_hist[tx_hash] = s


    def check_history(self):
        save = False
        mine_addrs = list(filter(lambda k: self.is_mine(self.history[k]), self.history.keys()))
        if len(mine_addrs) != len(self.history.keys()):
            save = True
        for addr in mine_addrs:
            hist = self.history[addr]

            for tx_hash, tx_height in hist:
                if tx_hash in self.pruned_txo.values() or self.txi.get(tx_hash) or self.txo.get(tx_hash):
                    continue
                tx = self.transactions.get(tx_hash)
                if tx is not None:
                    self.add_transaction(tx_hash, tx)
                    save = True
        if save:
            self.save_transactions()

    def basename(self):
        return os.path.basename(self.storage.path)

    def save_addresses(self):
        self.storage.put('addresses', {'receiving':self.receiving_addresses, 'change':self.change_addresses})

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if type(d) != dict: d={}
        self.receiving_addresses = d.get('receiving', [])
        self.change_addresses = d.get('change', [])

    def synchronize(self):
        pass

    def is_mine(self, address):
        return address in self.get_addresses()

    def get_address_index(self, address):
        if address in self.receiving_addresses:
            return False, self.receiving_addresses.index(address)
        if address in self.change_addresses:
            return True, self.change_addresses.index(address)
        raise Exception("Address not found", address)

    def get_local_height(self):
        """ return last known height if we are offline """
        return self.network.get_local_height() if self.network else self.storage.get('stored_height', 0)

    # return the total amount ever received by an address

    # return the balance of a bitcoin address: confirmed and matured, unconfirmed, unmatured
    def get_addresses(self):
        out = []
        out += self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out


    def relayfee(self):
        return relayfee(self.network)

    def dust_threshold(self):
        return dust_threshold(self.network)

    def address_is_old(self, address, age_limit=2):
        age = -1
        h = self.history.get(address, [])
        for tx_hash, tx_height in h:
            if tx_height == 0:
                tx_age = 0
            else:
                tx_age = self.get_local_height() - tx_height + 1
            if tx_age > age:
                age = tx_age
        return age > age_limit

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def add_address(self, address):
        if address not in self.history:
            self.history[address] = []

    def has_password(self):
        return self.storage.get('use_encryption', False)

    def check_password(self, password):
        self.keystore.check_password(password)

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore


    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.keystore.update_password(old_pw, new_pw)
        self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())



class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)

    def has_seed(self):
        return self.keystore.has_seed()

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)


    def create_new_address(self, for_change=False):
        assert type(for_change) is bool
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(addr_list)
        x = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(x)
        addr_list.append(address)
        self.save_addresses()
        self.add_address(address)
        return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change)
                continue
            if list(map(lambda a: self.address_is_old(a), addresses[-limit:] )) == limit*[False]:
                break
            else:
                self.create_new_address(for_change)

    def synchronize(self):
        with self.lock:
            if self.is_deterministic():
                self.synchronize_sequence(False)
                self.synchronize_sequence(True)
            else:
                if len(self.receiving_addresses) != len(self.keystore.keypairs):
                    pubkeys = self.keystore.keypairs.keys()
                    self.receiving_addresses = [self.pubkeys_to_address(i) for i in pubkeys]
                    self.save_addresses()
                    for addr in self.receiving_addresses:
                        self.add_address(addr)


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        try:
            xtype = bitcoin.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return bitcoin.pubkey_to_address(self.txin_type, pubkey)
