# p2wpkh-in-p2sh
An excruciatingly slow script which can be used for SegWit wallet recovery.

This script assumes you know the BIP39 seed phrase for a p2wpkh-in-p2sh (aka segwit or `m/49'/0'/0'`) wallet, but have forgotten part of the password.  Works with Trezor-style wallets.  Each test wallet takes approximately 1 second currently, so only makes sense to use if you have no other option or if you think you can guess the password with few tries.

## Requirements

Script is currently hardcoded to use `/usr/local/bin/python3` so you need that to exist.  You'll also need requirements:

    pip install -r requirements.txt

## Configuration

Open [test-pw.py](test-pw.py), and locate the `test_bip39_seed_bip49_p2sh_segwit` function.

Replace these two values with yours:

* `seed_words` (eg 'final round trust era topic march brain envelope spoon minimum bunker start')
* `address` (eg '3G2rhsBYmP6RKrjW1kVE1kJB9qjwggaCZw')

Then open [passwords.txt](passwords.txt) and add your passwords guesses (one per line).
I recommend using [btcrecover](https://github.com/gurnec/btcrecover) to generate thousand of possibilities.

You can using something like this to create many passwords with the `--listpass` option:

    btcrecover.py --listpass --tokenlist tokens.txt --typos-delete --typos-swap --typos-repeat --typos-case --typos-capslock --typos 2 --utf8 > passwords.txt

You'll have to create your own `tokens.txt` with tokens / patterns which you believe match your password.


## Usage

Script will generate virtual wallets with your `seed_words` + the password guesses and then check if the first address generated matches the expected `address` configured above.  You can run this command to see an example with the defaults:

    cat passwords.txt | ./test-pw.py 2> /dev/null


You can of course do fancy shell stuff like this to prefix every password with an `@` symbol:

    cat passwords.txt | sed 's/\(.*\)/@\1/' | ./test-pw.py 2> /dev/null


### TODO:

* Allow passing parameters for wallet on commandline
* Remove unused code / libraries (there is a lot)
* Optimize!  Library code was just copy / pasted from Electrum repo
* Consider improving `btcrecover` to support segwit + p2sh
