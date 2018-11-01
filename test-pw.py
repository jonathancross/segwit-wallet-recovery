#!/usr/bin/env python3
import sys
from lib.keystore import from_bip39_seed
from lib.storage import WalletStorage
from lib.wallet import Standard_Wallet

# Change this to be YOUR seed phrase:
SEED_WORDS = 'final round trust era topic march brain envelope spoon minimum bunker start'
# Change this to be the addresses the wallet might had.
POSSIBLE_ADDRESSES = [
    '3QZWeXoFxk3Sxr2rZ7iFGLBqGuYny4PGPE',
    '34xSpck4yJ3kjMWzaynKVFmzwY7u3KjoDC',
    '3PtdPR38hG3PbX5bqGD5gKXmXCY9fLtFi3',
    '3KurtNhsTjMjNCrp8PDEBZ7bpHnbh8W1sN',
]
# If you think any of your possible addresses must be among the first 3 addresses generated, then change this to 3
NUM_OF_ADDRESSES_TO_GENERATE = 5    # less is faster

def _create_standard_wallet(ks):
    store = WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', NUM_OF_ADDRESSES_TO_GENERATE)
    w = Standard_Wallet(store)
    w.synchronize()
    return w

def test_bip39_seed_bip49_p2sh_segwit(password):
    # The BIP32/43 path below could be made a parameter:
    ks = from_bip39_seed(SEED_WORDS, password, "m/49'/0'/0'")
    w = _create_standard_wallet(ks)
    for possible_address in POSSIBLE_ADDRESSES:
        for address in w.get_receiving_addresses():
            if ( possible_address == address):
                return True, address
    return False, None

def check_pass(password, failures):
    is_found, address = test_bip39_seed_bip49_p2sh_segwit(password)
    if (is_found):
        print(failures + '. FOUND!\npassword: "' + password + '"\naddress: "' + address +'"')
        sys.exit(1)
    else:
        print(failures + '. NOT: ' + password)
        return False

# Read passwords from STDIN and check them against known address above
failures = 1
for password in sys.stdin.read().split('\n'):
    if not check_pass(password, str(failures)):
        failures += 1
