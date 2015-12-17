Multichain Explorer - Alpha Notes

1. Follow ABE install instructions.

2. To launch Multichain Explorer:
python -m Abe.abe --config my_multichain.conf

By default, the explorer will be listening on port 2750, so in your browser visit:
localhost:2750

The example multichain config files can be used as a template.

3. MultiChain nodes must be online to see all data.  In future, the explorer should be able to operate in offline mode.

Misc Notes:
* https://github.com/bitcoin-abe/bitcoin-abe/blob/master/README-SQLITE.txt
* You can run two instances of the Explorer with the same config file, with one being passed the --no-serve argument.  That instance will keep on updating the database and not serve a web explorer.
* Example of just building a database
python -m Abe.abe --config multichain.conf --commit-bytes 10000 --no-serve
and then when you want to provide a web explorer:
python -m Abe.abe --config multichain.conf

