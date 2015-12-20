MultiChain Explorer (under heavy development, so things will change!)

MultiChain Explorer (MCE) is a fork of ABE to support MultiChain networks with assets and permissions.  MultiChain nodes must be online for all MCE functions to work.  In future, MCE should be able to operate in offline mode like ABE.

1. Install MCE.

Follow the standard ABE install instructions.

Note that if pycrypto is not on your system, you have to install:
sudo pip install pycrypto

If your Python setup is not complete, you may have to install:
sudo apt-get install python-dev
sudo apt-get install python-pip

2. Create MultiChain networks

Follow the MultiChain documentation to create a chain.  Skip this if you already have a chain you want to explore with  MCE.

Launch the chain to make sure it is running and that the genesis block has been found.

3. Update multichain.conf

The multichain.conf file should have a rpcuser and rpcpassword defined.  You should add the following entries:
rpcport=1234
address-checksum-value=11223344
Where both values can be found in params.dat.
In the future, we will try to automate this step (along with other manual configuration steps).

4. Configure the Explorer

The example MCE config files can be used as a template for your chain.

For an existing or newly created chain, using the MultiChain protocol, you will need information from the chain's param.dats file, normally found under $HOME/.multichain/NAME_OF_CHAIN/params.dat

Copy the magic handshake, address and script address bytes from params.dat into your MCE config file.

If you are installing MCE on a remote server and intend to access MCE over the internet, you must specify port and host information in the config file.  Change the host to the IP address of the server for testing, as by default it is localhost.  If your server does not have a static IP address, you can use 0.0.0.0 instead of hard-coding the IP address.


4. Launch Multichain Explorer

On your local computer:

python -m Abe.abe --config my_multichain.conf

By default, the explorer will be listening on port 2750 (or whatever you specified in your config file).

In your browser visit:
http://localhost:2750

On a remote server:

Typically you are connected to your remote server via SSH, so to avoid the connection terminating and shutting down MCE, use nohup:

nohup python -m Abe.abe --config my_multichain.conf &

In your browser visit:
http://IP_address_of_server:PORT



Misc Notes:
* https://github.com/bitcoin-abe/bitcoin-abe/blob/master/README-SQLITE.txt
* You can run two instances of the Explorer with the same config file, with one being passed the --no-serve argument.  That instance will keep on updating the database and not serve a web explorer.
* Example of just building a database
python -m Abe.abe --config multichain.conf --commit-bytes 10000 --no-serve
and then when you want to provide a web explorer:
python -m Abe.abe --config multichain.conf

