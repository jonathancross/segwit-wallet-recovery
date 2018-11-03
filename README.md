# SegWit P2SH

A script which can be used for SegWit wallet recovery.

This script assumes you know the [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed phrase for a p2wpkh-in-p2sh (aka [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) segwit defined by the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) path: `m/49'/0'/0'`) wallet, but have forgotten part of the password.  Works with Trezor-style wallets.  Each test wallet takes approximately 1 second currently, so only makes sense to use if you have no other option or if you think you can guess the password with few tries.

## Requirements

    pip install -r requirements.txt

## Configuration

Replace these values with yours:

* `SEED_WORDS` (eg 'final round trust era topic march brain envelope spoon minimum bunker start')
* `POSSIBLE_ADDRESSES` (eg ['3QZWeXoFxk3Sxr2rZ7iFGLBqGuYny4PGPE', '34xSpck4yJ3kjMWzaynKVFmzwY7u3KjoDC'])
* `NUM_OF_ADDRESSES_TO_GENERATE` (eg 5)

Then open [passwords.txt](passwords.txt) and add your passwords guesses (one per line).
I recommend using [btcrecover](https://github.com/gurnec/btcrecover) to generate thousand of possibilities.

You can use something like this to create many passwords with the `--listpass` option:

    btcrecover.py --listpass --tokenlist tokens.txt --typos-delete --typos-swap --typos-repeat --typos-case --typos-capslock --typos 2 --utf8 > passwords.txt

You'll have to create your own `tokens.txt` with tokens / patterns which you believe match your password.


## Usage

Script will generate virtual wallets with your `SEED_WORDS` + the password guesses, then generate as many addresses as configured in `NUM_OF_ADDRESSES_TO_GENERATE` and then check if any of the addresses generated matches any address in `POSSIBLE_ADDRESSES`.  You can run this command to see an example with the defaults:

    cat passwords.txt | python3 test-pw.py


You can of course do fancy shell stuff like this to prefix every password with an `@` symbol:

    cat passwords.txt | sed 's/\(.*\)/@\1/' | python3 test-pw.py


### TODO:

* Allow passing parameters for wallet on commandline
* Remove unused code / libraries (there is a lot)
* Optimize!  Library code was just copy / pasted from Electrum repo
* Consider improving `btcrecover` to support segwit + p2sh


## License

See [LICENSE](LICENSE).

This project was assembled with code taken from Electrum; those are Copyright © The Electrum Developers under the MIT License
