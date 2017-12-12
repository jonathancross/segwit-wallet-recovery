#!/usr/local/bin/python3
import sys
import lib.bitcoin as bitcoin
import lib.keystore as keystore
import lib.storage as storage
import lib.wallet as wallet

def _create_standard_wallet(ks):
    gap_limit = 1  # make tests run faster
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', gap_limit)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    return w

def test_bip39_seed_bip49_p2sh_segwit(password):
    # Change this to be YOUR seed phrase:
    seed_words = 'final round trust era topic march brain envelope spoon minimum bunker start'
    # Change this to be the address you want to generate.
    # This example is generated with the password 12345
    address = '3G2rhsBYmP6RKrjW1kVE1kJB9qjwggaCZw'
    # The BIP32/43 path below could be made a parameter:
    ks = keystore.from_bip39_seed(seed_words, password, "m/49'/0'/0'")
    w = _create_standard_wallet(ks)
    if (w.get_receiving_addresses()[0] == address):
        return True
    else:
        return False

def check_pass(password, failures):
    if (test_bip39_seed_bip49_p2sh_segwit(password)):
        print(failures + '. Found address for pw: ' + password)
        sys.exit(1)
    else:
        print(failures + '. NOT: ' + password)
        return False

# Read passwords from STDIN and check them against known address above
chars = ''
failures = 1

for c in sys.stdin.read():
    if c != '\n':
        chars += c
    else:
        password = chars
        chars = ''
        if not check_pass(password, str(failures)):
            failures += 1
