MultiChain Explorer
===================

MultiChain Explorer is a free block chain browser for MultiChain-based blockchains.

https://github.com/MultiChain/multichain-explorer

    Copyright(C) 2014,2015 by Coin Sciences Ltd.
    Copyright(C) 2011,2012,2013 by Abe developers.
    License: GNU Affero General Public License, see the file LICENSE.txt.
    Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.


Welcome to MultiChain Explorer!
===============================

This software reads the MultiChain block file, transforms and loads the
data into a database, and presents a web interface similar to that
popularized by Bitcoin block explorers, http://blockexplorer.com/.

MultiChain Explorer (Explorer) is a fork of the popular Abe project to add support for MultiChain networks with assets and permissions.  MultiChain nodes must be online for all Explorer functions to work.

MultiChain Explorer is currently under heavy development, so things will break/change!


System Requirements
-------------------

You must have Python 2.x installed on your system.

If pycrypto is not on your system, you will have to install it:

    sudo pip install pycrypto

If your Python setup is not complete, you may have to install:

    sudo apt-get install python-dev
    sudo apt-get install python-pip


Installation
------------

To install MultiChain explorer on your system:

    sudo python setup.py install

If you do not have root permission, or if you do not want to install for the whole sytem:

	python setup.py install --user

Before configuring the explorer, let's first make sure you have a MultiChain blockchain up and running.


Create and launch a MultiChain Network
--------------------------------------

Follow the [MultiChain documentation](http://www.multichain.com/download-install/) to install MultiChain and create a chain.  Skip this if you already have a chain you want to explore.

Launch the chain to make sure it is running and that the genesis block has been found.  The node you launch is what the Explorer will connect to.

    multichaind mychain -daemon

By default the runtime parameter ````txindex```` is enabled so that the node you launch will keep track of all transactions across the network, and not just the transactions for the node's wallet.  Do not disable this parameter. For more infomation about runtime parameters please visit http://www.multichain.com/developers/runtime-parameters/


Configure MultiChain.conf
-------------------------

The explorer will at times communicate with the MultiChain network using JSON-RPC.  The ````multichain.conf```` file should
have a rpcuser and rpcpassword defined.  You should add a value for the rpc port, which can be found in the ````params.dat````
file normally found in ````$HOME/.multichain/mychain/params.dat```` :

    rpcport=1234


Configure the Explorer
----------------------

The bundled example config files can be used as a template for your chain.

For an existing or newly created chain, the explorer will automatically read MultiChain specific parameters such as the magic handshake, address checksum, version and script version bytes from ````params.dat````.

If you are installing the explorer on a remote server and intend to access it over the internet, you must specify the explorer website's port and host information in the config file.  Change the host to the IP address of the server for testing, as by default it is localhost.  If your server does not have a static IP address, you can use ````0.0.0.0```` instead of hard-coding the IP address.


Launch the Explorer
-------------------

To run the explorer on your local computer:

    python -m Abe.abe --config mychain.conf

By default, the explorer will be listening for web requests on port 2750, unless you changed it in the Explorer's configuration file.  In your browser visit:

    http://localhost:2750

To run the explorer on a remote server, you must make sure the explorer does not shut down when you shut down your SSH terminal connection.

    nohup python -m Abe.abe --config mychain.conf &

In your browser visit:

    http://IP_address_of_server:PORT



Misc Notes
----------
* Currently it is not recommended to configure multiple chains in one config file as the search function does not search across chains for an address
* https://github.com/bitcoin-abe/bitcoin-abe/blob/master/README-SQLITE.txt
* You can run two instances of the Explorer with the same config file, with one being passed the --no-serve argument and the other --no-load, so that one instance only loads data into the database, and the other only serves web pages.
* Example of just building a database
python -m Abe.abe --config multichain.conf --commit-bytes 10000 --no-serve
and then when you want to provide a web explorer:
python -m Abe.abe --config multichain.conf --no-load


