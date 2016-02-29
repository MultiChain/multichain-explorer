MultiChain Explorer
===================

MultiChain Explorer is a free block chain browser for MultiChain-based blockchains.

https://github.com/MultiChain/multichain-explorer

    Copyright(C) 2015,2016 by Coin Sciences Ltd.
    Copyright(C) 2011,2012,2013 by Abe developers.
    License: GNU Affero General Public License, see the file LICENSE.txt.
    Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.


Welcome to MultiChain Explorer!
===============================

This software reads the MultiChain block file, transforms and loads the
data into a database, and presents a web interface similar to that
popularized by Bitcoin block explorers, http://blockexplorer.com/.

MultiChain Explorer (Explorer) is a fork of the popular Abe project to add support for MultiChain blockchains with assets and permissions.  MultiChain nodes must be online for all Explorer functions to work.

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

    cd multichain-explorer
    sudo python setup.py install

If you do not have root permission, or if you do not want to install for the whole sytem:

    cd multichain-explorer
    python setup.py install --user

The explorer will connect to a local MultiChain node.  Before configuring the explorer, let's first make sure you have a MultiChain blockchain up and running.


Create and launch a MultiChain Blockchain
-----------------------------------------

Follow the [MultiChain documentation](http://www.multichain.com/download-install/) to install MultiChain and create a chain named chain1.  Skip this if you already have a chain you want to explore.

Launch the chain to make sure it is running and that the genesis block has been found.  The node you launch is what the Explorer will connect to.

    multichaind chain1 -daemon

By default the runtime parameter ````txindex```` is enabled so that the node you launch will keep track of all transactions across the blockchain, and not just the transactions for the node's wallet.  Do not disable this parameter. For more infomation about runtime parameters please visit http://www.multichain.com/developers/runtime-parameters/


Configure MultiChain.conf
-------------------------

The explorer needs to communicate with the blockchain using JSON-RPC.  When you created the blockchain, the JSON-RPC connection details were automatically created by MultiChain and stored in a file named ````multichain.conf````.

The explorer will read this file.  If you examine the file you will see a username and password have been auto-generated.

    cd $HOME/.multichain/chain1/
    less multichain.conf

What you now need to do is add the RPC port number.

Copy the ````default-rpc-port```` value from ````params.dat```` and add an entry to ````multichain.conf```` as follows:

    cd $HOME/.multichain/chain1/
    less params.dat
    # Make a note of the default-rpc-port value, let's say it's 1234, and add it to multichain.conf
    echo "rpcport=1234" >>multichain.conf


Configure the Explorer
----------------------

The bundled example config file ````chain1.example.conf```` can be used as a template for your own chain.

    cd multichain-explorer
    cp chain1.example.conf chain1.conf

You can store the config file ````chain1.conf```` anywhere you want.  When you launch the explorer you can specify the location of your config file.  By default, it will look for a config file in the current directory.

So what changes should you make?

* Change ````port```` to the port number you want to serve web pages from.
* Change ````host```` to 0.0.0.0 if you want to serve web pages to anybody.
* Change ````dirname```` to match your chain name - by default it is chain1.
* Change ````chain```` based on how you want the chain to appear in the explorer.
* Change ````connect-args```` based on where you want to store the explorer database

Note: The explorer will automatically read MultiChain specific parameters such as the magic handshake, address checksum, version and script version bytes from ````params.dat````.  Please do not manually add these to your config file based on what you might see in ````abe.conf````.


Launch the Explorer
-------------------

To run the explorer on your local computer:

    cd multichain-explorer
    python -m Abe.abe --config chain1.conf

By default, the explorer will be listening for web requests on port 2750, unless you changed it in the Explorer's configuration file.  In your browser visit:

    http://localhost:2750

To run the explorer on a server, make sure the explorer is not accidently terminated when you close your SSH terminal connection

    cd multichain-explorer
    nohup python -m Abe.abe --config mychain.conf &

To check the explorer is runnning, in your browser visit:

    http://IP_address_of_server:2750


Reset the Explorer
----------------------

To start over with new chain data for a chain of the same name, simply:
1. Stop the explorer
2. Delete the explorer database file ````chain1.sqlite```` (path set in ````connect-args```` parameter in ````chain1.conf````)
3. Launch explorer (it may take some time to load the new chain)


Misc Notes
----------
* Currently it is not recommended to configure multiple chains in one config file as the search function does not search across chains for an address
* https://github.com/bitcoin-abe/bitcoin-abe/blob/master/README-SQLITE.txt
* You can run two instances of the Explorer with the same config file, with one being passed the --no-serve argument and the other --no-load, so that one instance only loads data into the database, and the other only serves web pages.
* Example of just building a database
python -m Abe.abe --config multichain.conf --commit-bytes 10000 --no-serve
and then when you want to provide a web explorer:
python -m Abe.abe --config multichain.conf --no-load


