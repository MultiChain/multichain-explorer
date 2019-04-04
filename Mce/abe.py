#!/usr/bin/env python
# Copyright(C) 2011,2012,2013,2014 by Abe developers.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

import sys
import os
import re
import types
from cgi import escape
import posixpath
import wsgiref.util
import time
import calendar
import logging
import json

import version
import DataStore
import readconf

# bitcointools -- modified deserialize.py to return raw transaction
import deserialize
import util  # Added functions.
import base58

# MULTICHAIN START
import Chain
import urllib
import binascii
import urllib2
import threading
# MULTICHAIN END

__version__ = version.__version__
# MULTICHAIN START
ABE_APPNAME = "MultiChain Explorer"
ABE_VERSION = __version__
ABE_URL = 'https://github.com/multichain/multichain-explorer'

COPYRIGHT_YEARS = '2011-2017'
COPYRIGHT = "Coin Sciences Ltd and Abe developers"
COPYRIGHT_URL = 'https://github.com/multichain/multichain-explorer'
# MULTICHAIN END

TIME1970 = time.strptime('1970-01-01','%Y-%m-%d')
EPOCH1970 = calendar.timegm(TIME1970)

# Abe-generated content should all be valid HTML and XHTML fragments.
# Configurable templates may contain either.  HTML seems better supported
# under Internet Explorer.
DEFAULT_CONTENT_TYPE = "text/html; charset=utf-8"
DEFAULT_HOMEPAGE = "chains"
# MULTICHAIN START
DEFAULT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->

    <title>%(title)s</title>

    <!-- Bootstrap and Theme -->
    <link href="%(dotdot)s%(STATIC_PATH)scss/bootstrap.min.css" rel="stylesheet">
    <link href="%(dotdot)s%(STATIC_PATH)scss/bootstrap-theme.min.css" rel="stylesheet">
    <link href="%(dotdot)s%(STATIC_PATH)sabe.css" rel="stylesheet">

    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="%(dotdot)s%(STATIC_PATH)sjs/jquery-1.11.3.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="%(dotdot)s%(STATIC_PATH)sjs/bootstrap.min.js"></script>
    <script src="%(dotdot)s%(STATIC_PATH)sabe.js"></script>

    %(myheader)s
</head>
<body>
    <div class="container">
	<table><td>
	<a title="Back to home" href="%(dotdot)s%(HOMEPAGE)s"><img src="%(dotdot)s%(STATIC_PATH)slogo32.png" alt="MultiChain logo" /></a>
	</td><td style="padding-left: 10px;" valign="middle">
	<h1>%(h1)s<h1>
	</td></table>
    %(body)s
    <!--<p><a href="%(dotdot)sq">API</a> (machine-readable pages)</p>-->
    <br><br>
    <p style="font-size: smaller">
        <span style="font-style: italic">
            Powered by <a href="%(ABE_URL)s">%(APPNAME)s</a>
        </span>
        %(download)s
    </p>
    </div>
</body>
</html>
"""
# MULTICHAIN END
DEFAULT_LOG_FORMAT = "%(message)s"

DEFAULT_DECIMALS = 8

# It is fun to change "6" to "3" and search lots of addresses.
ADDR_PREFIX_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{6,}\\Z')
HEIGHT_RE = re.compile('(?:0|[1-9][0-9]*)\\Z')
HASH_PREFIX_RE = re.compile('[0-9a-fA-F]{0,64}\\Z')
HASH_PREFIX_MIN = 6

NETHASH_HEADER = """\
blockNumber:          height of last block in interval + 1
time:                 block time in seconds since 0h00 1 Jan 1970 UTC
target:               decimal target at blockNumber
avgTargetSinceLast:   harmonic mean of target over interval
difficulty:           difficulty at blockNumber
hashesToWin:          expected number of hashes needed to solve a block at this difficulty
avgIntervalSinceLast: interval seconds divided by blocks
netHashPerSecond:     estimated network hash rate over interval

Statistical values are approximate and differ slightly from http://blockexplorer.com/q/nethash.

/chain/CHAIN/q/nethash[/INTERVAL[/START[/STOP]]]
Default INTERVAL=144, START=0, STOP=infinity.
Negative values back from the last block.
Append ?format=json to URL for headerless, JSON output.

blockNumber,time,target,avgTargetSinceLast,difficulty,hashesToWin,avgIntervalSinceLast,netHashPerSecond
START DATA
"""

NETHASH_SVG_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:abe="http://abe.bit/abe"
     viewBox="0 0 300 200"
     preserveAspectRatio="none"
     onload="Abe.draw(this)">

  <style>
    #chart polyline {
        stroke-width: 0.1%%;
        fill-opacity: 0;
        stroke-opacity: 0.5;
  </style>

  <script type="application/ecmascript"
          xlink:href="%(dotdot)s%(STATIC_PATH)snethash.js"/>

  <g id="chart">
    <polyline abe:window="1d" style="stroke: red;"/>
    <polyline abe:window="3d" style="stroke: orange;"/>
    <polyline abe:window="7d" style="stroke: yellow;"/>
    <polyline abe:window="14d" style="stroke: green;"/>
    <polyline abe:window="30d" style="stroke: blue;"/>

%(body)s

  </g>
</svg>
"""

# How many addresses to accept in /unspent/ADDR|ADDR|...
MAX_UNSPENT_ADDRESSES = 200

# MULTICHAIN START
def html_keyvalue_tablerow(key, *values):
    """
    Return string for a two column table row.
    Where the first element is the key and everything else is treated as the value
    """
    return '<tr><td>', key, '</td><td>', list(values), '</td></tr>'

def html_keyvalue_tablerow_wrap(minwidth, maxwidth, key, *values):
    """
    Return string for a two column table row, with word wrapping of <td> element.
    Where the first element is the key and everything else is treated as the value
    """
    return '<tr><td style="word-wrap: break-word;min-width: ', minwidth, 'px;max-width: ',maxwidth,'px;white-space:normal;">', key, '</td><td style="word-wrap: break-word;min-width: ',minwidth,'px;max-width: ',maxwidth,'px;white-space:normal;">', list(values), '</td></tr>'

# MULTICHAIN END

def make_store(args):
    store = DataStore.new(args)
    if (not args.no_load):
        store.catch_up()
    return store

class NoSuchChainError(Exception):
    """Thrown when a chain lookup fails"""

class PageNotFound(Exception):
    """Thrown when code wants to return 404 Not Found"""

class Redirect(Exception):
    """Thrown when code wants to redirect the request"""

class Streamed(Exception):
    """Thrown when code has written the document to the callable
    returned by start_response."""

class Abe:
    def __init__(abe, store, args):
        abe.store = store
        abe.args = args
        abe.htdocs = args.document_root or find_htdocs()
        abe.static_path = '' if args.static_path is None else args.static_path
        abe.template_vars = args.template_vars.copy()
        abe.template_vars['STATIC_PATH'] = (
            abe.template_vars.get('STATIC_PATH', abe.static_path))
        abe.template = flatten(args.template)
        abe.debug = args.debug
        abe.log = logging.getLogger(__name__)
        abe.log.info('Abe initialized.')
        abe.home = str(abe.template_vars.get("HOMEPAGE", DEFAULT_HOMEPAGE))
        if not args.auto_agpl:
            abe.template_vars['download'] = (
                abe.template_vars.get('download', ''))
        abe.base_url = args.base_url
        abe.address_history_rows_max = int(
            args.address_history_rows_max or 1000)

        if args.shortlink_type is None:
            abe.shortlink_type = ("firstbits" if store.use_firstbits else
                                  "non-firstbits")
        else:
            abe.shortlink_type = args.shortlink_type
            if abe.shortlink_type != "firstbits":
                abe.shortlink_type = int(abe.shortlink_type)
                if abe.shortlink_type < 2:
                    raise ValueError("shortlink-type: 2 character minimum")
            elif not store.use_firstbits:
                abe.shortlink_type = "non-firstbits"
                abe.log.warning("Ignoring shortlink-type=firstbits since" +
                                " the database does not support it.")
        if abe.shortlink_type == "non-firstbits":
            abe.shortlink_type = 10

# MULTICHAIN START
        abe.blockchainparams = {}
# MULTICHAIN END

    def __call__(abe, env, start_response):
        import urlparse

        page = {
            "status": '200 OK',
            "title": [escape(ABE_APPNAME), " ", ABE_VERSION],
            "body": [],
            "env": env,
            "params": {},
            "dotdot": "../" * (env['PATH_INFO'].count('/') - 1),
            "start_response": start_response,
            "content_type": str(abe.template_vars['CONTENT_TYPE']),
            "template": abe.template,
            "chain": None,
# MULTICHAIN START
            "myheader": []
# MULTICHAIN END
            }
        if 'QUERY_STRING' in env:
            page['params'] = urlparse.parse_qs(env['QUERY_STRING'])

        if abe.fix_path_info(env):
            abe.log.debug("fixed path_info")
            return redirect(page)

# MULTICHAIN START
        # First component of path is chain name
        symbol = wsgiref.util.shift_path_info(env)
        chain = None
        handler = None
        cmd = None
        try:
            chain = abe.chain_lookup_by_name(symbol)
            page['chain'] = chain
        except NoSuchChainError:
            cmd = symbol

        # If there is no chain, could be home page or resource
        if chain is None:
            if symbol.strip() == DEFAULT_HOMEPAGE:
                cmd = DEFAULT_HOMEPAGE
                handler = abe.get_handler(cmd)
            elif symbol == 'search':
                cmd = "search"
                handler = abe.get_handler(cmd)
                chain = abe.store.get_chain_by_id(1)
                page['chain'] = chain
        else:
            # Second component of path is the command
            cmd = wsgiref.util.shift_path_info(env)
            if cmd=='' or cmd is None:
                cmd = 'chain'
            handler = abe.get_handler(cmd)
# MULTICHAIN END

        tvars = abe.template_vars.copy()
        tvars['dotdot'] = page['dotdot']
        page['template_vars'] = tvars

        try:
            if handler is None:
                return abe.serve_static(cmd + env['PATH_INFO'], start_response)

            if (not abe.args.no_load):
                # Always be up-to-date, even if we means having to wait
                # for a response!  XXX Could use threads, timers, or a
                # cron job.
                abe.store.catch_up()

            handler(page)
        except PageNotFound:
            page['status'] = '404 Not Found'
            page['body'] = ['<p class="error">Sorry, ', env['SCRIPT_NAME'],
                            env['PATH_INFO'],
                            ' does not exist on this server.</p>']
        except NoSuchChainError as e:
            page['body'] += [
                '<p class="error">'
                'Sorry, I don\'t know about that chain!</p>\n']
        except Redirect:
            content=redirect(page)
            if isinstance(content, unicode):
                content = content.encode('latin-1') # Convert Unicode escaped bytes$
            return content
        except Streamed:
            return ''
        except Exception:
            abe.store.rollback()
            raise

        abe.store.rollback()  # Close implicitly opened transaction.

        start_response(page['status'],
                       [('Content-type', page['content_type']),
                        ('Cache-Control', 'max-age=30')])
# MULTICHAIN START
        tvars['myheader'] = flatten(page['myheader'])
# MULTICHAIN END
        tvars['title'] = flatten(page['title'])
        tvars['h1'] = flatten(page.get('h1') or page['title'])
        tvars['body'] = flatten(page['body'])
        if abe.args.auto_agpl:
            tvars['download'] = (
                ' <a href="' + page['dotdot'] + 'download">Source</a>')

        content = page['template'] % tvars
        if isinstance(content, unicode):
            content = content.encode('latin-1') # Convert Unicode escaped bytes into binary.  Used to be UTF-8.
        return [content]

# MULTICHAIN START
    # Return and cache blockchain params.  Empty dictionary is returned if there is an error.
    def get_blockchainparams(abe, chain):
        if len(abe.blockchainparams) > 0:
            return abe.blockchainparams
        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)
        params = {}
        try:
            params = util.jsonrpc(multichain_name, url, "getblockchainparams")
            assert(len(params['chain-protocol']) > 0)   # if we get invalid result, an exception is thrown
            abe.blockchainparams = params
        except Exception as e:
            pass # nop
        return params

# MULTICHAIN END

    def get_handler(abe, cmd):
        return getattr(abe, 'handle_' + cmd, None)

    def handle_chains(abe, page):
# MULTICHAIN START
        page['title'] = ABE_APPNAME
# MULTICHAIN END
        body = page['body']
        body += [
            abe.search_form(page),
# MULTICHAIN START
            '<table class="table table-striped">\n',
            '<tr><th>Status</th>',
            '<th>Chain</th>',
            '<th>Blocks</th>',
            '<th>Transactions</th>',
            #'<th>Time</th>',
            '<th>Assets</th>',
            '<th>Addresses</th>',
            '<th>Streams</th>',
            '<th>Peers</th>'
            '<th>Started</th><th>Age (days)</th>',
            #'<th>Coins Created</th>',
            #'<th>Avg Coin Age</th><th>',
            #'% <a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
            #'CoinDD</a></th>',
# MULTICHAIN END
            '</tr>\n']
        now = time.time() - EPOCH1970

        rows = abe.store.selectall("""
            SELECT c.chain_name, b.block_height, b.block_nTime, b.block_hash,
                   b.block_total_seconds, b.block_total_satoshis,
                   b.block_satoshi_seconds,
                   b.block_total_ss
              FROM chain c
              JOIN block b ON (c.chain_last_block_id = b.block_id)
             ORDER BY c.chain_name
        """)
        for row in rows:
            name = row[0]
            chain = abe.store.get_chain_by_name(name)
            if chain is None:
                abe.log.warning("Store does not know chain: %s", name)
                continue

# MULTICHAIN START
            num_txs = abe.store.get_number_of_transactions(chain)
            num_addresses = abe.store.get_number_of_addresses(chain)
            connection_status = True
            try:
                num_peers = abe.store.get_number_of_peers(chain)
                num_assets = abe.store.get_number_of_assets(chain)
                num_streams = abe.store.get_number_of_streams(chain)
            except Exception as e:
                connection_status = False
                abe.log.warning(e)
                num_assets = -1
                num_peers = -1
                num_streams = -1

            body += ['<tr><td>']
            if connection_status is True:
                body += '<span class="label label-success">Connected</span>'
            else:
                body += '<span class="label label-danger">No Connection</span>'
            body += ['</td>']

            body += [
                '<td><a href="', escape(name), '/chain">',
                escape(name), '</a></td>']  #<td>', escape(chain.code3), '</td>']
# MULTICHAIN END

            if row[1] is not None:
                (height, nTime, hash) = (
                    int(row[1]), int(row[2]), abe.store.hashout_hex(row[3]))

                body += [
# MULTICHAIN START
                    '<td><a href="', escape(name), '/blocks">', height, '</a></td>',
                    '<td>', num_txs, '</td>']
                    #'<td><a href="block/', hash, '">', height, '</a></td>',                    ]
                    #'<td>', format_time(nTime), '</td>']

                body += '<td>'
                if chain.__class__.__name__ is "MultiChain":
                    if num_assets == -1:
                        body += '?'
                    elif num_assets>=0:
                        body += ['<a href="{0}/assets">'.format(escape(chain.name)), num_assets, '</a>']
                else:
                    body += ['<td></td>']
                body += ['<td>', num_addresses, '</td>']
                body += '</td>'

                # Display number of streams in the chain
                body += '<td>'
                if chain.__class__.__name__ is "MultiChain":
                    if num_streams == -1:
                        body += '?'
                    elif num_streams == 0:
                        body += '0'
                    else:
                        body += ['<a href="{0}/streams">'.format(escape(chain.name)), num_streams, '</a>']
                else:
                    pass #body += ['<td></td>']
                #body += ['<td>', num_streams, '</td>']
                body += '</td>'

# MULTICHAIN END

                if row[6] is not None and row[7] is not None:
                    (seconds, satoshis, ss, total_ss) = (
                        int(row[4]), int(row[5]), int(row[6]), int(row[7]))

                    started = nTime - seconds
                    chain_age = now - started
                    since_block = now - nTime
# MULTICHAIN START
#                     if satoshis == 0:
#                         avg_age = '&nbsp;'
#                     else:
#                         avg_age = '%5g' % ((float(ss) / satoshis + since_block)
#                                            / 86400.0)
#                     if chain_age <= 0:
#                         percent_destroyed = '&nbsp;'
#                     else:
#                         more = since_block * satoshis
#                         denominator = total_ss + more
#                         if denominator <= 0:
#                             percent_destroyed = '&nbsp;'
#                         else:
#                             percent_destroyed = '%5g%%' % (
#                                 100.0 - (100.0 * (ss + more) / denominator))

                    body += [
                        '<td>',
                        '?' if num_peers is -1 else num_peers,
                        '</td>',
                        '<td>', format_time(started)[:10], '</td>',
                        '<td>', "{0:.1f}".format(chain_age / 86400.0), '</td>']
                        # '<td>', format_satoshis(satoshis, chain), '</td>',
                        # '<td>', avg_age, '</td>',
                        # '<td>', percent_destroyed, '</td>']
# MULTICHAIN END

            body += ['</tr>\n']
        body += ['</table>\n']
        if len(rows) == 0:
            body += ['<p>No block data found.</p>\n']

# MULTICHAIN START
        myheader = page['myheader']
        mempool_refresh_interval_ms = abe.store.recent_tx_interval_ms
        myheader += ['<script>'
                    '$(document).ready(function(){'
                    'setInterval(function(){'
                    '$("#recenttx").load(\'' + page['dotdot'] + urllib.quote(name, safe='') + '/recent?random=\' + Math.random().toString() )'
                    '}, ', mempool_refresh_interval_ms, ');'
                    '});'
                    '</script>']
        page_refresh_interval_secs = abe.store.home_refresh_interval_secs
        myheader += ['<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />',
                     '<meta http-equiv="Pragma" content="no-cache" />',
                     '<meta http-equiv="Expires" content="0" />']
        myheader += ['<meta http-equiv="refresh" content="', page_refresh_interval_secs, '" >']

        body += ['<div id="recenttx">']
        body += abe.create_recent_table(page, chain)
        body += ['</div>']


    def handle_recent(abe, page):
        chain = page['chain']
        page['template'] = "%(body)s"
        page['title'] = chain.name
        body = page['body']
        body += abe.create_recent_table(page, chain)


    def create_recent_table(abe, page, chain):
        """
        Create table of recent transactions via JSON-RPC and return list of HTML elements
        :param chain:
        :return:
        """
        body = []
        body += ['<h3>Latest Transactions</h3>'
            '<table class="table table-striped">\n',
            '<tr><th>Txid</th>', '<th>Type</th><th>Confirmation</th>'
            '<th>Time</th>',
            '</tr>\n']

        now = time.time() - EPOCH1970
        try:
            mempool = abe.store.get_rawmempool(chain)
            recenttx = abe.store.get_recent_transactions_as_json(chain, 10)
        except Exception as e:
            return ['<div class="alert alert-danger" role="warning">', e ,'</div>']

        sorted_mempool = sorted(mempool.items()[:10], key=lambda tup: tup[1]['time'], reverse=True)
        if len(sorted_mempool) < 10:
            sorted_recenttx = sorted(recenttx, key=lambda tx: tx['time'], reverse=True)
            existing_txids = [txid for (txid, value) in sorted_mempool]
            for tx in sorted_recenttx:
                if len(sorted_mempool) == 10:
                    break
                if tx['txid'] not in existing_txids:
                    existing_txids.append(tx['txid'])
                    sorted_mempool.append((tx['txid'], tx))

        for (k, v) in sorted_mempool:  # mempool.iteritems():
            txid = k
            diff = int(now - v['time'])
            if diff < 60:
                elapsed = "< 1 minute"
            elif diff < 3600:
                elapsed = "< " + str(int((diff / 60)+0.5)) + " minutes"
            elif diff < 3600*24*2:
                elapsed = "< " + str(int(diff / 3600)) + " hours"
            else:
                elapsed = str(int((diff / 3600) / 24)) + " days"


            body += ['<tr><td>']
            if abe.store.does_transaction_exist(txid):
                body += ['<a href="' + page['dotdot'] + escape(chain.name) + '/tx/' + txid + '">', txid, '</a>']
                labels = abe.store.get_labels_for_tx(txid, chain)
            else:
                body += ['<a href="' + page['dotdot'] + escape(chain.name) + '/mempooltx/' + txid + '">', txid, '</a>']
                json = None
                try:
                    json = abe.store.get_rawtransaction_decoded(chain, txid)
                except Exception:
                    pass

                if json is not None:
                    scriptpubkeys = [vout['scriptPubKey']['hex'] for vout in json['vout']]
                    labels = None
                    d = set()
                    for hex in scriptpubkeys:
                        binscript = binascii.unhexlify(hex)
                        tmp = abe.store.get_labels_for_scriptpubkey(chain, binscript)
                        d |= set(tmp)
                    labels = list(d)

            if labels is None:
                labels = []
            body += ['</td><td>']
            for label in labels:
                body += ['&nbsp;<span class="label label-primary">',label,'</span>']

            body += ['</td><td>']
            conf = v.get('confirmations', None)
            if conf is None or conf == 0:
                body += ['<span class="label label-default">Mempool</span>']
            else:
                body += ['<span class="label label-info">', conf, ' confirmations</span>']

            body += ['</td><td>', elapsed, '</td></tr>']


        body += ['</table>']
        return body

# MULTICHAIN END


    def chain_lookup_by_name(abe, symbol):
        if symbol is None:
            ret = abe.get_default_chain()
        else:
            ret = abe.store.get_chain_by_name(symbol)
        if ret is None:
            raise NoSuchChainError()
        return ret

    def get_default_chain(abe):
        return abe.store.get_default_chain()

    def format_addresses(abe, data, dotdot, chain):
# MULTICHAIN START
        checksum = chain.address_checksum
# MULTICHAIN END
        if data['binaddr'] is None:
            return 'Unknown'
        if 'subbinaddr' in data:
            # Multisig or known P2SH.
# MULTICHAIN START
            ret = [hash_to_address_link(chain.script_addr_vers, data['binaddr'], dotdot, text='Escrow', checksum=checksum),
                   ' ', data['required_signatures'], ' of']
            for binaddr in data['subbinaddr']:
                ret += [' ', hash_to_address_link(data['address_version'], binaddr, dotdot, 10, checksum=checksum)]
            return ret
        return hash_to_address_link(data['address_version'], data['binaddr'], dotdot, checksum=checksum)
# MULTICHAIN END

    def call_handler(abe, page, cmd):
        handler = abe.get_handler(cmd)
        if handler is None:
            raise PageNotFound()
        handler(page)

# MULTICHAIN_START
    def handle_chain(abe, page):
        chain = page['chain']

        #page['content_type'] = 'text/html'
        page['title'] = chain.name
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # high level stats
        num_txs = abe.store.get_number_of_transactions(chain)
        num_addresses = abe.store.get_number_of_addresses(chain)
        try:
            num_peers = abe.store.get_number_of_peers(chain)
            num_assets = abe.store.get_number_of_assets(chain)
        except Exception as e:
            abe.log.warning(e)
            num_assets = -1
            num_peers = -1

        try:
            num_streams = abe.store.get_number_of_streams(chain)
        except Exception as e:
            abe.log.warning(e)
            num_streams = -1

        info_resp = None
        params_resp = None
        try:
            info_resp = util.jsonrpc(multichain_name, url, "getinfo")
            params_resp = util.jsonrpc(multichain_name, url, "getblockchainparams")
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="alert">', e, '</div>']
            return

        body += ['<div class="container"><div class="row"><div class="col-md-6">']
        body += ['<h3>Summary</h3>']
        body += ['<table class="table table-bordered table-striped table-condensed">']
        body += ['<td>Blocks</td>', '<td><a href="', page['dotdot'], escape(chain.name), '/blocks/">', info_resp['blocks'], '</a></td>']
        #body += html_keyvalue_tablerow('Blocks', info_resp['blocks'])
        body += html_keyvalue_tablerow('Transactions', num_txs)
        body += ['<td>Assets</td>', '<td><a href="', page['dotdot'], escape(chain.name), '/assets">', num_assets, '</a></td>']
        #body += html_keyvalue_tablerow('Assets', num_assets)
        body += html_keyvalue_tablerow('Addresses', num_addresses)
        body += ['<td>Streams</td>', '<td><a href="', page['dotdot'], escape(chain.name), '/streams">', num_streams, '</a></td>']
        #body += html_keyvalue_tablerow('Streams', num_streams)
        body += ['</table>']
        body += ['<h3>General Information</h3>']
        body += ['<table class="table table-bordered table-striped table-condensed">']
        #body += ['<colgroup><col class="col-md-4"><col class="col-md-8"></colgroup>']
        for k,v in sorted(info_resp.items()):
            if k in ('nodeaddress', 'port'):
                continue
            if k in ('relayfee'):
                #v = '%.8g' % v # doesn't work?
                v = ('%.20f' % v).rstrip('0')  # so instead we force the number of decimal places and strip zeros
            body += html_keyvalue_tablerow(k, v)
        body += ['</table>']
        body += ['</div><div class="col-md-6">']
        body += ['<h3>Blockchain Parameters</h3>']
        body += ['<table class="table table-bordered table-striped table-condensed">']
        #body += ['<colgroup><col class="col-md-4"><col class="col-md-8"></colgroup>']
        for k,v in sorted(params_resp.items()):
            if k in ('default-network-port', 'default-rpc-port'):
                continue
            body += html_keyvalue_tablerow_wrap(50, 300, k, v)
        body += ['</table>']
        body += ['</div></div></div>'] # col, row, container


    def handle_blocks(abe, page):
        chain = page['chain']
# MULTICHAIN_END

        cmd = wsgiref.util.shift_path_info(page['env'])
        if cmd == '':
            page['env']['SCRIPT_NAME'] = page['env']['SCRIPT_NAME'][:-1]
            raise Redirect()
        if cmd == 'chain' or cmd == 'chains':
            raise PageNotFound()
        if cmd is not None:
            abe.call_handler(page, cmd)
            return

        page['title'] = chain.name

        body = page['body']
        body += abe.search_form(page)

        count = get_int_param(page, 'count') or 20
        hi = get_int_param(page, 'hi')
        orig_hi = hi

        if hi is None:
            row = abe.store.selectrow("""
                SELECT b.block_height
                  FROM block b
                  JOIN chain c ON (c.chain_last_block_id = b.block_id)
                 WHERE c.chain_id = ?
            """, (chain.id,))
            if row:
                hi = row[0]
        if hi is None:
            if orig_hi is None and count > 0:
                body += ['<p>I have no blocks in this chain.</p>']
            else:
                body += ['<p class="error">'
                         'The requested range contains no blocks.</p>\n']
            return

        rows = abe.store.selectall("""
            SELECT b.block_hash, b.block_height, b.block_nTime, b.block_num_tx,
                   b.block_nBits, b.block_value_out,
                   b.block_total_seconds, b.block_satoshi_seconds,
                   b.block_total_satoshis, b.block_ss_destroyed,
                   b.block_total_ss
              FROM block b
              JOIN chain_candidate cc ON (b.block_id = cc.block_id)
             WHERE cc.chain_id = ?
               AND cc.block_height BETWEEN ? AND ?
               AND cc.in_longest = 1
             ORDER BY cc.block_height DESC LIMIT ?
        """, (chain.id, hi - count + 1, hi, count))

        if hi is None:
            hi = int(rows[0][1])
        basename = os.path.basename(page['env']['PATH_INFO'])

        nav = ['<a href="',
               basename, '?count=', str(count), '">&lt;&lt;</a>']
        nav += [' <a href="', basename, '?hi=', str(hi + count),
                 '&amp;count=', str(count), '">&lt;</a>']
        nav += [' ', '&gt;']
        if hi >= count:
            nav[-1] = ['<a href="', basename, '?hi=', str(hi - count),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        nav += [' ', '&gt;&gt;']
        if hi != count - 1:
            nav[-1] = ['<a href="', basename, '?hi=', str(count - 1),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        for c in (20, 50, 100, 500):
            nav += [' ']
            if c != count:
                nav += ['<a href="', basename, '?count=', str(c)]
                if hi is not None:
                    nav += ['&amp;hi=', str(max(hi, c - 1))]
                nav += ['">']
            nav += [' ', str(c)]
            if c != count:
                nav += ['</a>']

        nav += [' <a href="', page['dotdot'], '">Search</a>']

        extra = False
        #extra = True
        body += ['<p>', nav, '</p>\n',
# MULTICHAIN START
                 '<table class="table table-striped"><tr><th>Block</th><th>Miner</th><th>Approx. Time</th>',
                 '<th>Transactions</th>',
                 #'<th>Value Out</th>',
                 #'<th>Difficulty</th><th>Outstanding</th>',
                 #'<th>Average Age</th>'
                 '<th>Chain Age</th>',
                 #'<th>% ',
                 #'<a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
                 #'CoinDD</a></th>',
# MULTICHAIN END
                 ['<th>Satoshi-seconds</th>',
                  '<th>Total ss</th>']
                 if extra else '',
                 '</tr>\n']
        for row in rows:
            (hash, height, nTime, num_tx, nBits, value_out,
             seconds, ss, satoshis, destroyed, total_ss) = row
            nTime = int(nTime)
            value_out = int(value_out)
            seconds = int(seconds)
            satoshis = int(satoshis)
            ss = int(ss)
            total_ss = int(total_ss)

            # if satoshis == 0:
            #     avg_age = '&nbsp;'
            # else:
            #     avg_age = '%5g' % (ss / satoshis / 86400.0)

            if total_ss <= 0:
                percent_destroyed = '&nbsp;'
            else:
                percent_destroyed = '%5g%%' % (100.0 - (100.0 * ss / total_ss))

# MULTICHAIN START
            miner_address = ''
            miner_block = None
            try:
                miner_block = abe.store.export_block(chain, block_number=height)
            except DataStore.MalformedHash:
                pass

            if miner_block is not None:
                miner_txout = miner_block['transactions'][0]['out'][0]
                if miner_txout['binaddr'] is not None:
                    miner_address = abe.format_addresses(miner_txout, page['dotdot'], chain)
                    #miner_address = miner_address[0:6]
                else:
                    try:
                        blockjson = abe.store.get_block_by_hash(chain, miner_block['hash'])
                        miner = blockjson['miner']
                        miner_address = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/address/' + miner + '">' + miner + '</a>'
                    except Exception:
                        miner_address = "Unknown"

            body += [
                '<tr><td><a href="', page['dotdot'], escape(chain.name), '/block/',
                abe.store.hashout_hex(hash),
                '">', height, '</a>'
                '</td><td>', miner_address,
                '</td><td>', format_time(int(nTime)),
                '</td><td>', num_tx,
                #'</td><td>', format_satoshis(value_out, chain),
                #'</td><td>', util.calculate_difficulty(int(nBits)),
                #'</td><td>', format_satoshis(satoshis, chain),
                #'</td><td>', avg_age,
                '</td><td>', '%5g' % (seconds / 86400.0),
                #'</td><td>', percent_destroyed,
                ['</td><td>', '%8g' % ss,
                 '</td><td>', '%8g' % total_ss] if extra else '',
                '</td></tr>\n']
# MULTICHAIN END

        body += ['</table>\n<p>', nav, '</p>\n']

    def _show_block(abe, page, dotdotblock, chain, **kwargs):
        body = page['body']

        try:
            b = abe.store.export_block(chain, **kwargs)
        except DataStore.MalformedHash:
            body += ['<p class="error">Not in correct format.</p>']
            return

        if b is None:
            body += ['<p class="error">Block not found.</p>']
            return

        in_longest = False
        for cc in b['chain_candidates']:
            if chain is None:
                chain = cc['chain']
            if chain.id == cc['chain'].id:
                in_longest = cc['in_longest']

        if in_longest:
# MULTICHAIN START
            page['title'] = [escape(chain.name), ' - Block ', b['height']]
            page['h1'] = ['<a href="', page['dotdot'], escape(chain.name), '/chain',
                          '?hi=', b['height'], '">',
                          escape(chain.name), '</a> ', b['height']]
        else:
            page['title'] = ['Block ', b['hash'][:4], '...', b['hash'][-10:]]

        # body += abe.short_link(page, 'b/' + block_shortlink(b['hash']))
# MULTICHAIN END

        is_stake_chain = chain.has_feature('nvc_proof_of_stake')
        is_stake_block = is_stake_chain and b['is_proof_of_stake']

# MULTICHAIN START
        try:
            blockjson = abe.store.get_block_by_hash(chain, b['hash'])
        except Exception as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        if b['hashPrev'] is not None or b['next_block_hashes'] is not None:
            body += ['<nav><ul class="pager">']
            if b['hashPrev'] is not None:
                body += ['<li class="previous"><a href="', dotdotblock,
                     b['hashPrev'], '"><span aria-hidden="true">&larr;</span> Older</a></li>']
            if b['next_block_hashes']:
                body += ['<li class="next"><a href="', dotdotblock, b['next_block_hashes'][0], '">Newer<span aria-hidden="true">&rarr;</span></a></li>']
            body += ['</ul></nav>']


        body += ['<h3>Block Summary</h3>\n']
        body += ['<table class="table table-bordered table-condensed">']

        if is_stake_chain:
            body += html_keyvalue_tablerow('Proof of Stake' if is_stake_block else 'Proof of Work', format_satoshis(b['generated'], chain), ' coins generated')

        body += html_keyvalue_tablerow('Hash', b['hash'])

        if b['hashPrev'] is not None:
            body += html_keyvalue_tablerow('Previous Block', '<a href="', dotdotblock,
                     b['hashPrev'], '">', b['hashPrev'], '</a>')

        if b['next_block_hashes']:
            body += ['<tr><td>Next Block</td>']
        for hash in b['next_block_hashes']:
            body += ['<td><a href="', dotdotblock, hash, '">', hash, '</a></td>']
        if b['next_block_hashes']:
            body += ['</tr>']

        body += html_keyvalue_tablerow('Height', b['height'] if b['height'] is not None else '')

        miner_txout = b['transactions'][0]['out'][0]
# MULTICHAIN START
        if miner_txout['binaddr'] is not None:
            miner_address = abe.format_addresses(miner_txout, page['dotdot'], chain)
        else:
            miner = blockjson['miner']
            miner_address = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/address/' + miner + '">' + miner + '</a>'
# MULTICHAIN END
        body += html_keyvalue_tablerow('Miner', miner_address)

        body += html_keyvalue_tablerow('Version', b['version'])
        body += html_keyvalue_tablerow('Transaction Merkle Root', b['hashMerkleRoot'])
        body += html_keyvalue_tablerow('Time', b['nTime'] , ' (' , format_time(b['nTime']) , ')')
        if False:
            body += html_keyvalue_tablerow('Difficulty', format_difficulty(util.calculate_difficulty(b['nBits'])) , ' (Bits: %x)' % (b['nBits']))
            body += html_keyvalue_tablerow('Cumulative Difficulty', format_difficulty(util.work_to_difficulty(b['chain_work'])) if b['chain_work'] is not None else '')


        body += html_keyvalue_tablerow('Nonce', b['nNonce'])
        body += html_keyvalue_tablerow('Transactions',len(b['transactions']))
        if False:
            body += html_keyvalue_tablerow('Value out', format_satoshis(b['value_out'], chain))
            body += html_keyvalue_tablerow('Transaction Fees', format_satoshis(b['fees'], chain))

        if False:
            body += html_keyvalue_tablerow('Average Coin Age', '%6g' % (b['satoshi_seconds'] / 86400.0 / b['chain_satoshis']) + ' days' if b['chain_satoshis'] and (b['satoshi_seconds'] is not None) else '')
            body += html_keyvalue_tablerow('Coin-days Destroyed', '' if b['satoshis_destroyed'] is None else format_satoshis(b['satoshis_destroyed'] / 86400.0, chain))
            body += html_keyvalue_tablerow('Cumulative Coin-days Destroyed', '%6g%%' %
             (100 * (1 - float(b['satoshi_seconds']) / b['chain_satoshi_seconds'])) if b['chain_satoshi_seconds'] else '')

        # ['sat=',b['chain_satoshis'],';sec=',seconds,';ss=',b['satoshi_seconds'],
        # ';total_ss=',b['chain_satoshi_seconds'],';destroyed=',b['satoshis_destroyed']]
        # if abe.debug else '',

        body += ['</table>']


        body += ['<h3>Transactions</h3>\n']

        body += ['<table class="table table-striped"><tr><th>Transaction</th>'
                 #<th>Fee</th>'
                 '<th>Size (kB)</th>'
                 #<th>From (amount)</th><th>To (amount)</th>'
                 '</tr>\n']
# MULTICHAIN END

        for tx in b['transactions']:
# MULTICHAIN START
            # Describe MultiChain specific transaction
            labels = []
            labeltype = 'success'
            try:
                mytx = abe.store.export_tx(tx_hash = tx['hash'], format = 'browser')
            except DataStore.MalformedHash:
                mytx = None

            if mytx is not None:
                for txout in mytx['out']:
                    # reset label for each txout, but labeltype we can retain as it impacts entire transaction
                    label = None

                    # Commenting out below as we do we want to see what all outputs are upto
                    # if label is not None:
                    #     # we have found the main purpose of this tx
                    #     break

                    script_type, data = chain.parse_txout_script(txout['binscript'])
                    if script_type in [Chain.SCRIPT_TYPE_MULTICHAIN, Chain.SCRIPT_TYPE_MULTICHAIN_P2SH]:
                        data = util.get_multichain_op_drop_data(txout['binscript'])
                        if data is not None:
                            opdrop_type, val = util.parse_op_drop_data(data, chain)
                            label = util.get_op_drop_type_description(opdrop_type)
                        else:
                            label = 'Unknown MultiChain command'
                            labeltype = 'danger'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN:
                        opreturn_type, val = util.parse_op_return_data(data, chain)
                        label = util.get_op_return_type_description(opreturn_type)

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_STREAM:
                        label = 'Create Stream'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_FILTER:
                        label = 'Create Filter'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM:
                        label = 'Stream Item'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_ENTITY_PERMISSION:
                        label = 'Approval or Entity Permission'

                    elif script_type in [Chain.SCRIPT_TYPE_MULTICHAIN_SPKN, Chain.SCRIPT_TYPE_MULTICHAIN_SPKU]:
                        data = util.get_multichain_op_drop_data(txout['binscript'])
                        if data is not None:
                            opdrop_type, val = util.parse_op_drop_data(data, chain)
                            label = util.get_op_drop_type_description(opdrop_type)
                        else:
                            label = 'Unknown MultiChain command'
                            labeltype = 'danger'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_SPKF:
                        label = "Inline Data"

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_APPROVE:
                        label = "Approve Upgrade"

                    if label is not None:
                        labels.append(label)

                    if "spkd" in txout['binscript']:
                        labels.append("Inline Data")

            if len(labels) == 0:
                labelclass = ''
            else:
                labelclass='class="' + labeltype + '"'
            body += ['<tr ' + labelclass + '><td><a href="../tx/' + tx['hash'] + '">',
                     tx['hash'], '</a>']
                     # tx['hash'][:16], '...</a>']

            if len(labels)>0:
                body += ['<div>']
                for label in labels:
                    body += ['<span class="label label-' + labeltype + '">', label, '</span>&nbsp;']
                body += ['</div>']

            body += [
                     #'</td><td>', format_satoshis(tx['fees'], chain),
# MULTICHAIN END
                     '</td><td>', tx['size'] / 1000.0,
                     '</td><td>']

#             if tx is b['transactions'][0]:
#                 body += [
#                     'POS ' if is_stake_block else '',
# # MULTICHAIN START
#                     'Generation: ', format_satoshis(b['generated'], chain),
#                     #' + ', format_satoshis(b['fees'], chain), ' total fees'
#                 ]
# # MULTICHAIN END
#             else:
#                 for txin in tx['in']:
#                     body += [abe.format_addresses(txin, page['dotdot'], chain), ': ',
#                              format_satoshis(txin['value'], chain), '<br />']
#
#             body += ['</td><td>']
#             for txout in tx['out']:
#                 if is_stake_block:
#                     if tx is b['transactions'][0]:
#                         assert txout['value'] == 0
#                         assert len(tx['out']) == 1
#                         body += [
#                             format_satoshis(b['proof_of_stake_generated'], chain),
#                             ' included in the following transaction']
#                         continue
#                     if txout['value'] == 0:
#                         continue
#
#                 if txout['binaddr'] is None:
#                     label = miner_address
#                 else:
#                     label = abe.format_addresses(txout, page['dotdot'], chain)
#                 body += [label, ': ',
#                          format_satoshis(txout['value'], chain), '<br />']
#
#             body += ['</td></tr>\n']
        body += '</table>\n'

    def handle_block(abe, page):

        z = page['env']['PATH_INFO']

        block_hash = wsgiref.util.shift_path_info(page['env'])
        if block_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        block_hash = block_hash.lower()  # Case-insensitive, BBE compatible
        page['title'] = 'Block'

        if not is_hash_prefix(block_hash):
            page['body'] += ['<p class="error">Not a valid block hash.</p>']
            return

        abe._show_block(page, '', None, block_hash=block_hash)

    def handle_tx(abe, page):
        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

# MULTICHAIN START
        output_json = False
        if tx_hash.endswith('.json'):
            tx_hash = tx_hash[:-5]
            output_json = True
# MULTICHAIN END

        tx_hash = tx_hash.lower()  # Case-insensitive, BBE compatible
        page['title'] = ['Transaction ', tx_hash[:10], '...', tx_hash[-4:]]
        body = page['body']

        if not is_hash_prefix(tx_hash):
            body += ['<p class="error">Not a valid transaction hash.</p>']
            return

# MULTICHAIN START
        if output_json:
            body += ['<p class="error">JSON output not yet implemented.</p>']
            return
# MULTICHAIN END

        try:
            # XXX Should pass chain to export_tx to help parse scripts.
            tx = abe.store.export_tx(tx_hash = tx_hash, format = 'browser')
        except DataStore.MalformedHash:
            body += ['<p class="error">Not in correct format.</p>']
            return

        if tx is None:
            body += ['<p class="error">Transaction not found.</p>']
            return

        return abe.show_tx(page, tx)

    def get_assets_by_txid_fragment(abe, chain):
        result = {}
        try:
            resp = abe.store.get_assets(chain)
            for o in resp:
                txid = o.get('issuetxid',None)
                if txid is not None:
                    fragment = txid[0:32]   # first 16 hex chars
                    result[fragment] = o
        except Exception as e:
            print "Exception:", e

        return result

# MULTICHAIN START

    def show_tx_row_to_html_impl(abe, chain, body, asset_txid_dict, binscript, script_type, data, v_json, data_ref):
        body += ['<td style="max-width: 400px;">', escape(decode_script(binscript)) ]
        msg = None
        msgtype = 'success'
        msgpanelstyle = ''
        if script_type in [Chain.SCRIPT_TYPE_MULTICHAIN,
                           Chain.SCRIPT_TYPE_MULTICHAIN_P2SH,
                           Chain.SCRIPT_TYPE_MULTICHAIN_FILTER,
                           Chain.SCRIPT_TYPE_MULTICHAIN_STREAM,
                           Chain.SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM,
                           Chain.SCRIPT_TYPE_MULTICHAIN_SPKN,  # also matches template used for input cache opdrop
                           Chain.SCRIPT_TYPE_MULTICHAIN_SPKF,
                           Chain.SCRIPT_TYPE_MULTICHAIN_SPKU,
                           Chain.SCRIPT_TYPE_MULTICHAIN_APPROVE]:
            # NOTE: data returned above is pubkeyhash, due to common use to get address, so we extract data ourselves.
            data = util.get_multichain_op_drop_data(binscript)
            if data is not None:
                opdrop_type, val = util.parse_op_drop_data(data, chain)
                if opdrop_type==util.OP_DROP_TYPE_ISSUE_ASSET:
                    # Not the most efficient way, but will suffice for now until assets are stored in a database table.
                    try:
                        asset = abe.store.get_asset_by_name(chain, tx['hash'])
                        display_amount = util.format_display_quantity(asset, val)
                        assetref = asset['assetref'] or asset['name']
                        link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>'
                        msg = "Issue {0} units of new asset {1}".format(display_amount, link)
                    except Exception as e:
                        msg = "Issue {0:d} raw units of new asset".format(val)
                elif opdrop_type==util.OP_DROP_TYPE_ISSUE_MORE_ASSET:
                    dict = val[0]
                    quantity = dict['quantity']
                    if chain.protocol_version < 10007:
                        assetref = dict['assetref'] or dict['name']
                    else:
                        asset_dict = asset_txid_dict[dict['assetref']]
                        assetref = asset_dict['assetref'] or asset_dict['name']
                    link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>'
                    try:
                        asset = abe.store.get_asset_by_name(chain, assetref)
                        assetname = asset.get('name',assetref)
                        link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetname.encode('unicode-escape') + '</a>'
                        display_amount = util.format_display_quantity(asset, quantity)
                        msg = "Issue {0} more units of {1}".format(display_amount, link)
                    except Exception as e:
                        msg = "Issue {0:d} more raw units of asset {1}".format(val, link)
                elif opdrop_type==util.OP_DROP_TYPE_SEND_ASSET:
                    msg = ""
                    msgparts = []
                    for dict in val:
                        quantity = dict['quantity']
                        if chain.protocol_version < 10007:
                            assetref = dict['assetref'] or dict['name']
                        else:
                            asset_dict = asset_txid_dict[dict['assetref']]
                            assetref = asset_dict['assetref'] or asset_dict['name']

                        # link shows asset ref
                        link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>'

                        # Not the most efficient way, but will suffice for now until assets are stored in a database table.
                        try:
                            asset = abe.store.get_asset_by_name(chain, assetref)
                            display_amount = util.format_display_quantity(asset, quantity)
                            # update link to display name, if not anonymous, instead of assetref
                            assetname = asset.get('name',assetref)
                            if len(assetname)>0:
                                link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetname.encode('unicode-escape') + '</a>'
                            msgparts.append("{0} units of asset {1}".format(display_amount, link))
                        except Exception as e:
                            msgparts.append("{0} raw units of asset {1}".format(quantity, link))

                    msg += '<br>'.join(msgparts)
                elif opdrop_type == util.OP_DROP_TYPE_RAW_DATA:
                    msg = "Data: " + util.render_long_data_with_popover(val)

                elif opdrop_type==util.OP_DROP_TYPE_PERMISSION:
                    if val['filter']:
                        msg = "{} Filter".format("Approve" if val['type'] == 'grant' else "Reject")
                    else:
                        permissions = [permission_type for permission_type in (
                            'connect', 'send', 'receive', 'write', 'issue', 'create', 'mine', 'high1', 'high2', 'high3',
                            'admin', 'activate', 'upgrade', 'low1', 'low2', 'low3') if val[permission_type]]

                        msg = val['type'].capitalize() + " "
                        msg += ' permission for '
                        msg += ', '.join("{0}".format(item) for item in permissions)

                    if val['type'] is 'grant' and not (val['startblock']==0 and val['endblock']==4294967295):
                        msg += ' (blocks {0} - {1} only)'.format(val['startblock'], val['endblock'])
                elif opdrop_type in [util.OP_DROP_TYPE_CREATE_STREAM, util.OP_DROP_TYPE_SPKN_CREATE_STREAM]:
                    msg = 'Create stream:'
                    if chain.protocol_version < 10007:
                        data = util.get_multichain_op_return_data(binscript)
                        opreturn_type, val = util.parse_op_return_data(data, chain)
                        fields = val['fields']
                    else:
                        fields = val # for 10007, val already contains the fields
                    msg += '<table class="table table-bordered table-condensed">'
                    for k,v in sorted(fields.items()):
                        try:
                            v.decode('ascii')
                        except UnicodeDecodeError:
                            v = util.long_hex(v)
                        # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"

                elif opdrop_type == util.OP_DROP_TYPE_SPKN_CREATE_FILTER:
                    msg = "Create filter"
                    fields = val
                    msg += '<table class="table table-bordered table-condensed">'
                    for k,v in sorted(fields.items()):
                        try:
                            v.decode('ascii')
                        except UnicodeDecodeError:
                            v = util.long_hex(v)
                        # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"

                # 20001
                elif opdrop_type == util.OP_DROP_TYPE_SPKN_CREATE_UPGRADE:
                    msg = "Create upgrade"
                    try:
                        resp = abe.store.list_upgrades(chain)
                        for upgrade in resp:
                            if upgrade["name"] == val["Name"]:
                                msg += '<table class="table table-bordered table-condensed">'
                                msg += '<tr><td>Name</td><td>{0}</td>'.format(upgrade["name"])
                                for k, v in upgrade["params"].items():
                                    msg += '<tr><td>{0}</td><td>{1}</td>'.format(k, v)
                                msg += '</table>'
                                break
                    except Exception as e:
                        pass
                    msgpanelstyle="margin-bottom: -20px;"

                # 10007
                elif opdrop_type==util.OP_DROP_TYPE_SPKN_NEW_ISSUE:
                    msg = 'New Issuance Metadata:'
                    msg += '<table class="table table-bordered table-condensed">'
                    fields = val
                    for k,v in sorted(fields.items()):
                        # try:
                        #     v.decode('ascii')
                        # except UnicodeDecodeError:
                        #     v = util.long_hex(v)
                        # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"
                    msgtype = 'danger'

                # 10007
                elif opdrop_type==util.OP_DROP_TYPE_SPKI:
                    msg = 'Input Cache:'
                    msg += '<table class="table table-bordered table-condensed">'
                    fields = val
                    for k,v in sorted(fields.items()):
                        decodedscript = escape(decode_script(v))
                        # try:
                        #     v.decode('ascii')
                        # except UnicodeDecodeError:
                        #     v = util.long_hex(v)
                        # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(), decodedscript)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, decodedscript)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"
                    msgtype = 'danger'

                # 10007
                #elif opdrop_type==util.OP_DROP_TYPE_FOLLOW_ON_ISSUANCE_METADATA:
                elif opdrop_type==util.OP_DROP_TYPE_SPKE and script_type==Chain.SCRIPT_TYPE_MULTICHAIN_SPKU:
                    script_type, dict = chain.parse_txout_script(binscript)
                    # dict keys contain opdrop data: assetidentifier, assetdetails

                    opdrop_spke = dict['assetidentifier']
                    opdrop_type, assettxid = util.parse_op_drop_data(opdrop_spke, chain)

                    opdrop_spku = dict['assetdetails']
                    opdrop_type, fields = util.parse_op_drop_data(opdrop_spku, chain)

                    asset_dict = asset_txid_dict[assettxid]
                    assetref = asset_dict['assetref'] or asset_dict['name']
                    assetname = asset_dict['name']
                    link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetname.encode('unicode-escape') + '</a>'

                    msg = "Follow-on issuance metadata for {0}".format(link)
                    msg += '<table class="table table-bordered table-condensed">'
                    for k,v in sorted(fields.items()):
                        # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"

                elif (opdrop_type==util.OP_DROP_TYPE_SPKE and script_type==Chain.SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM) or opdrop_type == util.OP_DROP_TYPE_STREAM_ITEM:

                # legacy 10006
                #elif opdrop_type == util.OP_DROP_TYPE_STREAM_ITEM:
                    msg = ''
                    script_type, dict = chain.parse_txout_script(binscript)
                    txidfragment = val
                    streamlink = 'Invalid: ' + val

                    try:
                        resp = abe.store.list_streams(chain)
                        for stream in resp:
                            if stream.get('createtxid','').startswith(txidfragment):
                                streamname = stream.get('name','')
                                streamlink = '<a href="../../' + escape(chain.name) + '/stream/' + streamname + '">' + streamname + '</a>'
                                break

                    except Exception as e:
                        body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
                        return

                    # itemkey = dict['itemkey'][4:] # we don't need prefix 'spkk' or 0x73 0x70 0x6b 0x6b
                    itemkeys = [itemkey[4:] for itemkey in dict['itemkeys']]
                    msg += '<table class="table table-bordered table-condensed">'
                    msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format('Stream', streamlink)
                    msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format('Key', ', '.join(itemkeys))

                    for item in v_json.get("items", []):
                        itemdata = item["data"]
                        if isinstance(itemdata, types.DictType):
                            text_data = itemdata.get("text", "") or json.dumps(itemdata.get("json", ""))
                            data_html = util.render_long_data_with_popover(text_data)
                        else:
                            try:
                                text_data = itemdata.decode('hex').decode('ascii')
                                data_html = util.render_long_data_with_popover(text_data)
                            except Exception:
                                data_html = util.render_long_data_with_link(itemdata, data_ref)
                        msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format('Data', data_html)
                    msg += '</table>'
                    msgpanelstyle="margin-bottom: -20px;"

                elif opdrop_type == util.OP_DROP_TYPE_SPKE and script_type == Chain.SCRIPT_TYPE_MULTICHAIN_APPROVE:
                    msg = "Approve upgrade"
                    msg += '<table class="table table-bordered table-condensed">'
                    try:
                        resp = abe.store.list_upgrades(chain)
                        for upgrade in resp:
                            if upgrade.get("createtxid", "").startswith(val):
                                msg += '<tr><td>Name</td><td>{0}</td>'.format(upgrade["name"])
                                for k, v in upgrade["params"].items():
                                    msg += '<tr><td>{0}</td><td>{1}</td>'.format(k, v)
                                break
                    except Exception as e:
                        pass
                    parts = v_json["scriptPubKey"]["asm"].split()
                    approval = parts[2][8:10]
                    msg += '<tr><td>Approval</td><td>{0}</td>'.format(approval == '01')
                    msg += '</table>'
                    msgpanelstyle = "margin-bottom: -20px;"

        if script_type is Chain.SCRIPT_TYPE_MULTICHAIN_ENTITY_PERMISSION:
            # If this output is not signed by an address with admin (to change activate or write) or activate (to change write) permission for the stream, the transaction is invalid. On the protocol level we will allow permission flags other than admin/activate/write, but these will be forbidden/hidden in the APIs for now. "
            script_type, dict = chain.parse_txout_script(binscript)

            opdrop_spke = dict['txid']
            opdrop_type, txidfragment = util.parse_op_drop_data(opdrop_spke, chain)

            # Figure out if the txid is for an asset or a stream
            asset = asset_txid_dict.get(txidfragment, None)
            if asset is not None:
                assetref = asset['assetref'] or asset['name']
                entityname = asset.get('name', '')
                entitylink = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + entityname.encode('unicode-escape') + '</a>'
            else:
                try:
                    resp = abe.store.list_streams(chain)
                    for stream in resp:
                        if stream.get('createtxid','').startswith(txidfragment):
                            entityname = stream.get('name','')
                            entitylink = '<a href="../../' + escape(chain.name) + '/streams/' + entityname + '">' + entityname + '</a>'
                            break
                except Exception as e:
                    body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
                    return


            opdrop_spkp = dict['permissions']
            opdrop_type, val = util.parse_op_drop_data(opdrop_spkp, chain)

            if val['filter']:
                msg = "{} Filter".format("Approve" if val['type'] == 'grant' else "Reject")
            else:
                if val['type'] is 'grant':
                    msg = 'Grant permission to '
                else:
                    msg = 'Revoke permission to '

                permissions = []
                if val['admin']:
                    permissions += ['Admin']
                if val['activate']:
                    permissions += ['Activate']
                if val['write']:
                    permissions += ['Write']
                if val['create']:
                    permissions += ['Create']
                if val['issue']:
                    permissions += ['Issue']

                msg += ', '.join("{0}".format(item) for item in permissions)

            msg += ' on '
            if asset is not None:
                msg += 'asset '
            else:
                msg += 'stream '
            msg += entitylink

            if val['type'] is 'grant' and not (val['startblock']==0 and val['endblock']==4294967295):
                msg += ' (blocks {0} - {1} only)'.format(val['startblock'], val['endblock'])

        if script_type is Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN:
            opreturn_type, val = util.parse_op_return_data(data, chain)
            if opreturn_type==util.OP_RETURN_TYPE_ISSUE_ASSET:

                msg = 'Issued asset details:'
                msg += '<table class="table table-bordered table-condensed">'

                # try to create a link for the asset
                assetName = val['name']
                assetLink = assetName
                try:
                    asset = abe.store.get_asset_by_name(chain, assetName)
                    assetref = asset['assetref'] or asset['name']
                    assetLink = '<a href="../assetref/{0}">{1}</a>'.format(asset['assetref'], assetName)
                except Exception:
                    pass

                msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format('Name',assetLink)
                msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format('Multiplier',val['multiplier'])
                fields = val['fields']
                for k,v in sorted(fields.items()):
                    try:
                        v.decode('ascii')
                    except UnicodeDecodeError:
                        v = util.long_hex(v)
                    # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                    msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                msg += '</table>'
                msgpanelstyle="margin-bottom: -20px;"

            elif opreturn_type==util.OP_RETURN_TYPE_SPKC:
                msg = 'Issue more asset details:'
                msg += '<table class="table table-bordered table-condensed">'

                fields = val['fields']
                for k,v in sorted(fields.items()):
                    try:
                        v.decode('ascii')
                    except UnicodeDecodeError:
                        v = util.long_hex(v)
                    # msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k.capitalize(),v)
                    msg += '<tr><td>{0}</td><td>{1}</td></tr>'.format(k, v)
                msg += '</table>'
                msgpanelstyle="margin-bottom: -20px;"

            elif opreturn_type==util.OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE:
                msg = 'Miner block signature'
                msgtype = 'info'
                msgpanelstyle="margin-bottom: -20px; word-break:break-all;"
            else:
                msgpanelstyle="word-break:break-word;"

        # if v_json and not msg:
        if v_json:
            has_msg = bool(msg)
            if not msg:
                msg = ""
            if "data" in v_json:
                msg += '<table class="table table-bordered table-condensed">'
                for item in v_json["data"]:
                    if any(x in item for x in ("text", "json")):
                        if "text" in item:
                            data = item["text"]
                        else:
                            data = json.dumps(item["json"])
                        item_html = util.render_long_data_with_popover(data)
                    else:
                        if bytearray.fromhex(item[:6]) in (b"spk", b"SPK"):
                            item = item[8:]
                        item_html = util.render_long_data_with_link(item, data_ref)
                    msg += "<tr><td>{}</td></tr>".format(item_html)
                msg += "</table>"
                msgpanelstyle = "margin-bottom: -20px;"
            if not has_msg:
                if "assets" in v_json:
                    msgparts = []
                    for item in (x for x in v_json["assets"] if x["type"] == "transfer"):
                        quantity = item['qty']
                        assetref = item.get('assetref') or item.get('name')

                        # link shows asset ref
                        link = '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>'

                        # Not the most efficient way, but will suffice for now until assets are stored in a database table.
                        try:
                            asset = abe.store.get_asset_by_name(chain, assetref)
                            display_amount = util.format_display_quantity(asset, quantity)
                            # update link to display name, if not anonymous, instead of assetref
                            assetname = item.get('name', assetref)
                            if assetname:
                                link = '<a href="../../' + escape(
                                    chain.name) + '/assetref/' + assetref + '">' + assetname.encode(
                                    'unicode-escape') + '</a>'
                            msgparts.append("{0} units of asset {1}".format(display_amount, link))
                        except Exception as e:
                            msgparts.append("{0} raw units of asset {1}".format(quantity, link))
                    msg += '<br>'.join(msgparts)
                if "items" in v_json:
                    for item in (x for x in v_json["items"] if x["type"] == "stream"):
                        stream_name = item["name"]
                        keys = [item["key"]] if "key" in item else item["keys"]
                        data = item["data"]
                        if item.get("offchain", False):
                            item_data = item["data"]
                            n_chunks = len(item["chunks"])
                            data_html = '<a href="{}">{} bytes of off-chain {} data in {} chunk{}</a>'.format(
                                data_ref, item_data["size"], item_data["format"], n_chunks, "s" if n_chunks > 1 else "")
                        else:
                            if any(x in data for x in ("text", "json")):
                                if "text" in data:
                                    data = data["text"]
                                else:
                                    data = json.dumps(data["json"])
                                data_html = util.render_long_data_with_popover(data)
                            else:
                                data_html = util.render_long_data_with_link(data, data_ref)
                        stream_link = '<a href="../../{0}/stream/{1}">{1}</a>'.format(escape(chain.name), stream_name)
                        keys_html = ', '.join(keys)
                        msg += """
                            <table class="table table-bordered table-condensed">
                                <tr><td>Stream</td><td>{}</td></tr>
                                <tr><td>Keys</td><td>{}</td></tr>
                                <tr><td>Data</td><td>{}</td></tr>
                            </table>
                        """.format(stream_link, keys_html, data_html)
                    msgpanelstyle = "margin-bottom: -20px;"

        # Add MultiChain HTML
        if msg is not None:
            body += ['<div style="height:5px;"></div><div class="panel panel-default panel-'+msgtype+'"><div class="panel-body" style="' + msgpanelstyle + '">'+msg+'</div></div>']

        body += [ '</td>\n']


    def show_tx(abe, page, tx):
        body = page['body']
        asset_txid_dict = {}    # map: txid fragment (first 16 bytes as hex string) --> asset obj

        def row_to_html(v, row, this_ch, other_ch, no_link_text):
            txid = row['o_hash']
            urlprefix = ''
            binscript = row['binscript']

            body = page['body']
            body += [
                '<tr>\n',
                '<td><a name="', this_ch, row['pos'], '">', row['pos'],
                '</a></td>\n<td>']
            if txid is None:
                body += [no_link_text]
            else:
                body += [
                    '<a href="', urlprefix, txid, '#', other_ch, v,
                    '">', txid[:10], '...:', v, '</a>']
            body += ['</td>']

            # Decode earlier as we need to use script type
            novalidaddress=False
            script_type = data = None
            if binscript is not None:
                script_type, data = chain.parse_txout_script(binscript)
                if script_type in [Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_FILTER,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_STREAM,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_SPKN,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_SPKF,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_SPKU]:
                    novalidaddress = True

            p2sh_flag = False
            if row['binaddr'] is None and txid is None:
                if novalidaddress is False:
                    try:
                        blockjson = abe.store.get_block_by_hash(chain, blk_hash)
                        miner = blockjson['miner']
                        addressLabel = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/address/' + miner + '">' + miner + '</a>'
                    except Exception:
                        addressLabel = 'Unknown (not connected)'
                else:
                    addressLabel = 'None'
            else:
                addressLabel = abe.format_addresses(row, '../', chain)
            body += [
                '</td>\n',
                '<td>', format_satoshis(row['value'], chain, abe), '</td>\n',
                '<td>', addressLabel]
            if row['address_version'] is chain.script_addr_vers:
                p2sh_flag = True

            if p2sh_flag is True:
                body += ['<div><span class="label label-info">P2SH</span></div>']
            body += [ '</td>\n']

            if binscript is not None:
                if this_ch == 'o':
                    tx_json = util.jsonrpc(chain_name, chain_url, "getrawtransaction", tx["hash"], 1)
                    v_json = tx_json['vout'][int(v)]
                    dataref = '{}/{}/txoutdata/{}/{}'.format(page['dotdot'], escape(chain.name), tx["hash"], v)
                else:
                    v_json = dataref = None
                abe.show_tx_row_to_html_impl(chain, body, asset_txid_dict, binscript, script_type, data, v_json, dataref)

            body += ['</tr>\n']

        # body += abe.short_link(page, 't/' + hexb58(tx['hash'][:14]))
        body += ['<table class="table table-bordered table-condensed">']
        body += html_keyvalue_tablerow('Hash', tx['hash'])
# MULTICHAIN END
        chain = None
        is_coinbase = None

        for tx_cc in tx['chain_candidates']:
            if chain is None:
                chain = tx_cc['chain']
                is_coinbase = (tx_cc['tx_pos'] == 0)
            elif tx_cc['chain'].id != chain.id:
                abe.log.warning('Transaction ' + tx['hash'] + ' in multiple chains: '
                             + tx_cc['chain'].id + ', ' + chain.id)

            blk_hash = tx_cc['block_hash']
# MULTICHAIN START
            body += html_keyvalue_tablerow('Appeared in',
                '<a href="../block/', blk_hash, '">',
                escape(tx_cc['chain'].name), ', Block ',
                tx_cc['block_height'] if tx_cc['in_longest'] else [blk_hash[:10], '...', blk_hash[-4:]],
                '</a> (', format_time(tx_cc['block_nTime']), ')'
                )
# MULTICHAIN END

        if chain is None:
            abe.log.warning('Assuming default chain for Transaction ' + tx['hash'])
            chain = abe.get_default_chain()
        chain_name = abe.store.get_multichain_name_by_id(chain.id)
        chain_url = abe.store.get_url_by_chain(chain)
# MULTICHAIN START
        body += html_keyvalue_tablerow('Number of inputs', len(tx['in']),
            ' &ndash; <a href="#inputs">jump to inputs</a>')
        #body += html_keyvalue_tablerow('Total in', format_satoshis(tx['value_in'], chain))
        body += html_keyvalue_tablerow('Number of outputs', len(tx['out']),
            ' &ndash; <a href="#outputs">jump to outputs</a>')
        #body += html_keyvalue_tablerow('Total out', format_satoshis(tx['value_out'], chain))
        body += html_keyvalue_tablerow('Size', tx['size'], ' bytes')
        if False:
            body += html_keyvalue_tablerow('Fee', format_satoshis(0 if is_coinbase else
                                     (tx['value_in'] and tx['value_out'] and
                                      tx['value_in'] - tx['value_out']), chain))
        body += ['</table>']
        body += ['<p class="text-right">']
        body += [' <a role="button" class="btn btn-default btn-xs" href="../rawtx/', tx['hash'], '">Bitcoin JSON</a>']
        body += [' <a role="button" class="btn btn-default btn-xs" href="../rpctxjson/', tx['hash'], '">MultiChain JSON</a>']
        body += [' <a role="button" class="btn btn-default btn-xs" href="../rpctxraw/', tx['hash'], '">MultiChain Hex</a>']
        body += ['</p>']
# MULTICHAIN END

# MULTICHAIN START

        asset_txid_dict = abe.get_assets_by_txid_fragment(chain)

        body += ['<a name="inputs"><h3>Inputs</h3></a>\n<table class="table table-striped">\n',
                 '<tr><th>Index</th><th>Previous output</th><th>Native</th>',
# MULTICHAIN END
                 '<th>From address</th>']
        if abe.store.keep_scriptsig:
            body += ['<th>ScriptSig</th>']
        body += ['</tr>\n']
        for vin, txin in enumerate(tx['in']):
            row_to_html(vin, txin, 'i', 'o',
                        'Generation' if is_coinbase else 'Unknown')
        body += ['</table>\n',
# MULTICHAIN START
                 '<a name="outputs"><h3>Outputs</h3></a>\n<table class="table table-striped">\n',
                 '<tr><th>Index</th><th>Redeemed at input</th><th>Native</th>',
# MULTICHAIN END
                 '<th>To address</th><th>ScriptPubKey</th></tr>\n']
        for vout, txout in enumerate(tx['out']):
            row_to_html(vout, txout, 'o', 'i', 'Not yet redeemed')

        body += ['</table>\n']

# MULTICHAIN START
    def show_mempool_tx_json(abe, page, tx):

        asset_txid_dict = {}    # map: txid fragment (first 16 bytes as hex string) --> asset obj

        def row_to_html(v, row, this_ch, other_ch, no_link_text, tx):
            txid = row.get('txid') or tx["txid"]
            # if input tx is in the database, show the correct url
            urlprefix = '../tx/' if abe.store.does_transaction_exist(txid) else ''
            # binscript
            if this_ch is 'i':
                binscript = binascii.unhexlify(row['scriptSig']['hex'])
            else:
                binscript = binascii.unhexlify(row['scriptPubKey']['hex'])

            body = page['body']
            body += [
                '<tr>\n',
                '<td><a name="', this_ch, row['pos'], '">', row['pos'],
                '</a></td>\n<td>']
            if txid is None:
                body += [no_link_text]
            else:
                body += [
                    '<a href="', urlprefix, txid, '#', other_ch, v,
                    '">', txid[:10], '...:', v, '</a>']
            body += ['</td>']

            # Decode earlier as we need to use script type
            novalidaddress=False
            script_type = data = None
            if binscript is not None:
                script_type, data = chain.parse_txout_script(binscript)
                if script_type in [Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_FILTER,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_STREAM,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_SPKN,
                                   Chain.SCRIPT_TYPE_MULTICHAIN_SPKU]:
                    novalidaddress = True

            p2sh_flag = False
            addressLabel = 'None'
            value = 0

            # tx_json = util.jsonrpc(chain_name, chain_url, "getrawtransaction", txid, 1)
            # v_json = tx_json['vout'][int(vout)]
            if this_ch == 'o':
                tx_json = util.jsonrpc(chain_name, chain_url, "getrawtransaction", txid, 1)
                v_json = tx_json['vout'][int(v)]
            else:
                v_json = None

            if novalidaddress is False:
                if this_ch is 'i':
                    try:
                        addressLabel = v_json['scriptPubKey']['addresses'][0]
                        value = v_json['value']
                    except Exception as e:
                        pass
                else:
                    try:
                        addressLabel = row['scriptPubKey']['addresses'][0]
                        value = row['value']
                    except Exception as e:
                        pass

            if addressLabel is not 'None':
                version, pubkeyhash = util.decode_address_multichain(addressLabel)
                if version is chain.script_addr_vers:
                    p2sh_flag = True
                addressLabel = '<a href="../address/' + addressLabel + '">' + addressLabel + '</a>'

            body += [
                '</td>\n',
                '<td>', value, '</td>\n', # value is already in currency format, does not require calling format_satoshis
                '<td>', addressLabel]

            if p2sh_flag is True:
                body += ['<div><span class="label label-info">P2SH</span></div>']
            body += [ '</td>\n']

            if binscript is not None:
                dataref = '{}/{}/txoutdata/{}/{}'.format(page['dotdot'], escape(chain.name), txid, v)
                abe.show_tx_row_to_html_impl(chain, body, asset_txid_dict, binscript, script_type, data, v_json, dataref)

            body += ['</tr>\n']

        body = page['body']

        # body += abe.short_link(page, 't/' + hexb58(tx['hash'][:14]))
        body += ['<table class="table table-bordered table-condensed">']
        body += html_keyvalue_tablerow('Hash', tx['txid'])
        chain = page['chain']

        asset_txid_dict = abe.get_assets_by_txid_fragment(chain)

        chain_name = abe.store.get_multichain_name_by_id(chain.id)
        chain_url = abe.store.get_url_by_chain(chain)

        is_coinbase = tx.get('coinbase', None)

        body += html_keyvalue_tablerow('Appeared in', escape(chain.name) + ' (Mempool)')
        body += html_keyvalue_tablerow('Number of inputs', len(tx['vin']),
            ' &ndash; <a href="#inputs">jump to inputs</a>')
        body += html_keyvalue_tablerow('Number of outputs', len(tx['vout']),
            ' &ndash; <a href="#outputs">jump to outputs</a>')
        body += html_keyvalue_tablerow('Size', len(tx['hex']), ' bytes')
        body += ['</table>']


        body += ['<a name="inputs"><h3>Inputs</h3></a>\n<table class="table table-striped">\n',
                 '<tr><th>Index</th><th>Previous output</th><th>Native</th>',
                 '<th>From address</th>']
        #if abe.store.keep_scriptsig:
        body += ['<th>ScriptSig</th>']
        body += ['</tr>\n']
        for vin, txin in enumerate(tx['vin']):
            txin['pos'] = vin
            row_to_html(vin, txin, 'i', 'o',
                        'Generation' if is_coinbase else 'Unknown', tx)

        body += ['</table>\n',
                 '<a name="outputs"><h3>Outputs</h3></a>\n<table class="table table-striped">\n',
                 '<tr><th>Index</th><th>Redeemed at input</th><th>Native</th>',
                 '<th>To address</th><th>ScriptPubKey</th></tr>\n']
        
        for vout, txout in enumerate(tx['vout']):
            txout['pos'] = vout
            row_to_html(vout, txout, 'o', 'i', 'Not yet redeemed', tx)

        body += ['</table>\n']
# MULTICHAIN END

    def handle_rawtx(abe, page):
        abe.do_raw(page, abe.do_rawtx)

# MULTICHAIN START

    def handle_address(abe, page):
        chain = page['chain']

        # Shift asset ref
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        #page['content_type'] = 'text/html'
        page['title'] = "Address " + address
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # check the address
        version, pubkeyhash = util.decode_check_address_multichain(address)
        if pubkeyhash is None:
            raise PageNotFound()
            #raise MalformedAddress("Invalid address")

        # If the HTML link for this handler gets only created for MultiChain networks, we don't need to check class.
        #if chain.__class__.__name__ is "MultiChain":
        body += ['<h3>Permissions</h3>']
        try:
            resp = util.jsonrpc(multichain_name, url, "listpermissions", "all", address)
            if len(resp) > 0 :
                body += ['<ul>']
                for permission in resp:
                    name = permission['type'].capitalize()
                    start = permission['startblock']
                    end = permission['endblock']
                    range = ""
                    if not (start==0 and end==4294967295):
                        range = " (blocks {0} - {1} only)".format(start, end)
                    body += ['<li>', name, range, '</li>']
                body += ['</ul>']
        except util.JsonrpcException as e:
            msg= "Failed to get permissions for address: JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            msg= "Failed to get permissions for address: I/O error({0}): {1}".format(e.errno, e.strerror)
            body += ['<div class="alert alert-danger" role="alert">', msg, '</div>']
            return

        # Display native currency if the blockchain has one
        if abe.get_blockchainparams(chain).get('initial-block-reward', 0) > 0:
            body += ['<h3>Native Balance</h3>']
            try:
                resp = util.jsonrpc(multichain_name, url, "getaddressbalances", address)
                if len(resp) is 0:
                    body += ['None']
                else:
                    body += ['<ul>']
                    for balance in resp:
                        if str(balance['assetref']) is '':
                            body += ['<li>', str(balance['qty']), '</li>']
                    body += ['</ul>']
            except util.JsonrpcException as e:
                msg= "Failed to get balance for address: JSON-RPC error({0}): {1}".format(e.code, e.message)
                body += ['<div class="alert alert-danger" role="warning">', msg, '</div>']
                return
            except IOError as e:
                msg= "Failed to get balance for address: I/O error({0}): {1}".format(e.errno, e.strerror)
                body += ['<div class="alert alert-danger" role="alert">', msg, '</div>']
                return

        body += ['<h3>Asset Balances</h3>']
        try:
            row = abe.store.selectrow("""select pubkey_id from pubkey where pubkey_hash = ?""",
                                      (abe.store.binin(pubkeyhash),) )
            assets_resp = abe.store.get_assets(chain)
            if len(assets_resp) is 0:
                body += ['None']
            elif row is not None:
                pubkey_id = int(row[0])

                # s = json.dumps(assets_resp, sort_keys=True, indent=2)
                # body += ['<pre>', s, '</pre>']

                body += ['<table class="table table-striped"><tr>'
                         '<th>Asset Name</th>'
                         '<th>Asset Reference</th>'
                         '<th>Transactions</th>'
                         '<th>Raw Units</th>'
                         '<th>Balance</th>'
                         '</tr>']

                assetdict = {}
                for asset in assets_resp:
                    # use escaped form as dict key
                    name = asset.get('name','').encode('unicode-escape')
                    assetdict[name] = asset

                for row in abe.store.selectall("""
                    select a.name, a.prefix, b.balance from asset_address_balance b join asset a on (a.asset_id=b.asset_id)
                    where b.balance>0 and b.pubkey_id=?""",
                                       (pubkey_id, )):
                    name, prefix, balance = row
                    if name is None:
                        name=''
                    name = name.encode('unicode-escape')
                    asset = assetdict[ name ]
                    assetref = asset['assetref']

                    num_tx = abe.store.get_number_of_transactions_for_asset_address(chain, assetref, pubkey_id)

                    if assetref.endswith(str(prefix)):
                        balance_display_qty = util.format_display_quantity(asset, balance)
                        body += ['<tr><td><a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + name + '</a>',
                             '</td><td><a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>',
                             '</td><td><a href="../../' + escape(chain.name) + '/assetaddress/' + address + '/' + assetref + '">' + str(num_tx) + '</a>',
                             '</td><td>', balance,
                             '</td><td>', balance_display_qty,
                             '</td></tr>']
                body += ['</table>']
        except Exception as e:
            body += ['<div class="alert alert-danger" role="alert">', 'Failed to get asset information: '+str(e), '</div>']
            pass


    # Given an address and asset reference, show transactions for that address and asset
    def handle_assetaddress(abe, page):
        chain = page['chain']

        # shift address
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, ''): # or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        # Shift asset ref
        assetref = wsgiref.util.shift_path_info(page['env'])
        if assetref in (None, '') or page['env']['PATH_INFO'] != '':
             raise PageNotFound()

        page['title'] = 'Address ' + address + ' transactions'
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # get asset information and issue tx as json
        try:
            resp = util.jsonrpc(multichain_name, url, "listassets", assetref)
            asset = resp[0]
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            # Example error: JSON-RPC error(-8): Asset with this reference not found: 5-264-60087
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        name = asset.get('name','').encode('unicode-escape')
        body += ['<h3>' + name.capitalize() + ' (' + assetref + ')</h3>']

        transactions = abe.store.get_transactions_for_asset_address(chain, assetref, address)
        if transactions is None:
            body += ['No transactions']
            return
        body += ['<table class="table table-condensed"><tr>'
                 '<th>Transaction</th>'
                 '<th>Block</th>'
                 # '<th>Net Change</th>'
                 '</tr>\n']


        # local method to get raw units for a given asset from a txin or txout,
        def get_asset_amount_from_txinout(tx, this_ch, other_ch, asset, chain):
            binaddr = tx['binaddr']
            if binaddr is None:
                return 0
            checksum = chain.address_checksum
            vers = tx['address_version'] # chain.script_addr_ver
            if checksum is None:
                addr = util.hash_to_address(vers, binaddr)
            else:
                addr = util.hash_to_address_multichain(vers, binaddr, checksum)
            matchaddress = (addr==address)

            binscript = tx['binscript']
            if binscript is None:
                return 0

            # for input, we want to examine the txout it represents
            if this_ch=='i':
                binscript = tx['multichain_scriptPubKey']

            script_type, data = chain.parse_txout_script(binscript)

            if script_type not in [Chain.SCRIPT_TYPE_MULTICHAIN, Chain.SCRIPT_TYPE_MULTICHAIN_P2SH]:
                return 0

            data = util.get_multichain_op_drop_data(binscript)
            if data is None:
                return 0
            opdrop_type, val = util.parse_op_drop_data(data, chain)
            if opdrop_type==util.OP_DROP_TYPE_ISSUE_ASSET:
                if matchaddress: # and this_ch=='o':
                    return val
                return 0
            elif opdrop_type==util.OP_DROP_TYPE_SEND_ASSET or opdrop_type==util.OP_DROP_TYPE_ISSUE_MORE_ASSET:
                for dict in val:
                    quantity = dict['quantity']
                    assetref = dict['assetref']
                    if assetref == asset['assetref']:
                        if matchaddress:
                            return quantity
            return 0

        for tx in transactions:
            tx_hash = tx['hash']
            try:
                t = abe.store.export_tx(tx_hash = tx_hash, format = 'browser')
            except DataStore.MalformedHash:
                continue
            if t is None:
                continue

            out_amount = 0
            for txobj in t['out']:
                qty = get_asset_amount_from_txinout(txobj, 'o', 'i', asset, chain)
                out_amount = out_amount + qty
            in_amount = 0
            for txobj in t['in']:
                qty = get_asset_amount_from_txinout(txobj, 'i', 'o', asset, chain)
                in_amount = in_amount + qty

            # net_amount = out_amount - in_amount
            # net_amount_label = util.format_display_quantity(asset, net_amount)
            # if net_amount == 0:
            #     context = ""
            # elif net_amount > 0:
            #     context = "success"
            # else:
            #     context = "danger"

            # contextclass='class="' + context + '"'
            body += ['<tr><td><a href="../../../' + escape(chain.name) + '/tx/' + tx['hash'] + '">', tx['hash'], '</a>',    # shorten via tx['hash'][:16]
                     '</td><td><a href="../../../' + escape(chain.name) + '/block/', tx['blockhash'], '">', tx['height'], '</a>',
                     # '</td><td ' + contextclass + '>', net_amount_label,
                     '</td></tr>']
        body += ['</table>']



    # Given an asset reference, display info about asset.
    def handle_assetref(abe, page):
        chain = page['chain']

        # Shift asset ref
        assetref = wsgiref.util.shift_path_info(page['env'])
        if assetref in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = 'Asset'
        page['h1'] = '<a href="../assets/">' + chain.name + '</a>'
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # get block height from assetref
        m = re.search('^(\d+)-\d+-\d+$', assetref)
        height = int(m.group(1)) if m else None

        # get asset information and issue tx as json
        try:
            resp = util.jsonrpc(multichain_name, url, "listassets", assetref, True) # verbose to get 'issues' field
            asset = resp[0]
            issuetxid = asset['issuetxid']
            resp = util.jsonrpc(multichain_name, url, "getrawtransaction", issuetxid, 1)
            issuetx = resp
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        blocktime = issuetx['blocktime']
        blockhash = issuetx['blockhash']
        name = issuetx['vout'][0]['assets'][0].get('name','')
        address_to = issuetx['vout'][0]['scriptPubKey']['addresses'][0]
        address_from = asset['issues'][0]['issuers'][0]
        native_amount = issuetx['vout'][0]['value']

        issues = asset.get('issues', [])
        num_issues = len(issues)
        raw_units = asset['issueraw']
        display_qty = util.format_display_quantity(asset, raw_units)


        name = name.encode('unicode-escape') # escaped text will at the final stage be encoded to 'latin-1' i.e. 0-255 bytes.
        body += ['<h3>Asset Summary "' + name + '"</h3>\n']
        body += ['<table class="table table-bordered table-condensed">']

        if height:
            body += html_keyvalue_tablerow('Issue Block Height', '<a href="../../' + escape(chain.name) + '/block/', blockhash, '">', height, '</a>')
#                                                                                                                '' b['height'] if b['height'] is not None else '')
        body += html_keyvalue_tablerow('Issue Block Time', blocktime , ' (' , format_time(blocktime) , ')')
        body += html_keyvalue_tablerow('Issue TXID', '<a href="../../' + escape(chain.name) + '/tx/' + issuetxid + '">', issuetxid, '</a>')
        body += html_keyvalue_tablerow('Asset Reference', '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + assetref + '</a>')
        body += html_keyvalue_tablerow('Name', '<a href="../../' + escape(chain.name) + '/assetref/' + assetref + '">' + name + '</a>')
        holders = abe.store.get_number_of_asset_holders(chain, assetref)
        body += html_keyvalue_tablerow('Addresses holding units', holders, ' &ndash; <a href="#holders">jump to holders</a>')
        if num_issues>0:
            body += html_keyvalue_tablerow('Asset Issues', num_issues, ' &ndash; <a href="#issues">jump to issues</a>')
        body += html_keyvalue_tablerow('Raw units issued', raw_units)
        body += html_keyvalue_tablerow('Display quantity', display_qty)
        body += html_keyvalue_tablerow('Native amount sent', format_satoshis(native_amount, chain))
        body += html_keyvalue_tablerow('Issuer Address', '<a href="../../' + escape(chain.name) + '/address/' + address_from + '">', address_from, '</a>')
        body += html_keyvalue_tablerow('Issue Recipient Address ', '<a href="../../' + escape(chain.name) + '/address/' + address_to + '">', address_to, '</a>')
        body += ['</table>']

        #body += ['<h3>', asset['name'], '(Asset Reference ', assetref, ')', '</h3>']
        body += ['<p class="text-right">']
        body += ['<button href="#RawJson" class="btn btn-default btn-xs" data-toggle="collapse">MultiChain JSON</button>']
        body += ['<div id="RawJson" class="collapse"><pre>', json.dumps(resp, sort_keys=True, indent=2), '</pre></div></p>']
        #body += [' <a role="button" class="btn btn-default btn-xs" href="../rawtx/', tx['hash'], '">Bitcoin JSON</a>']

        # Show asset issues with display amount and details
        if num_issues>0:
            body += ['<a name="issues"><h3>Asset Issues</h3></a>']
            body += ['<table class="table table-condensed"><tr>'
                     '<th>Txid</th>'
                     '<th>Issue Amount</th>'
                     '<th>Details</th>'
                     '</tr>\n']
            for issue in issues:
                issue_txid = issue['txid']
                body += ['<tr>'
                         '<td><a href="../../' + escape(chain.name) + '/tx/' + issue_txid + '">', issue_txid[:8], '...</a>']

                issue_raw = issue['raw']
                issue_display_qty = util.format_display_quantity(asset, issue_raw)
                body += ['<td>', issue_display_qty, '</td>']

                issue_details = issue.get('details', {})
                if "json" in issue_details:
                    issue_details = issue_details["json"]
                body += ['<td>']
                if issue_details:
                    body += ['<table class="table table-bordered table-striped table-condensed">']
                    for k,v in sorted(issue_details.items()):
                        if isinstance(v, bytes):
                            try:
                                v.decode('ascii')
                            except UnicodeDecodeError:
                                v = util.long_hex(v)
                        else:
                            v = json.dumps(v)
                        body += html_keyvalue_tablerow(k, v)
                    body += ['</table>']
                body += ['</td>'
                         '</tr>']
            body += ['</table>']

        # List asset holders and balances
        body += ['<a name="holders"><h3>Asset Holders </h3></a>\n']
        body += ['<table class="table table-striped"><tr>'
                 '<th>Address</th>'
                 '<th>Balance</th>'
                 '</tr>\n']
        holders = abe.store.get_asset_holders(chain, assetref)
        for holder in holders:
# MULTICHAIN START
            pubkeyhash = holder['pubkey_hash']
            if (holder['pubkey_flags'] & DataStore.PUBKEY_FLAGS_P2SH) > 0:
                vers = chain.script_addr_vers
            else:
                vers = chain.address_version
            checksum = chain.address_checksum
            if checksum is None:
                address = util.hash_to_address(vers, pubkeyhash)
            else:
                address = util.hash_to_address_multichain(vers, pubkeyhash, checksum)

            amount = util.format_display_quantity(asset, float( holder['balance'] ))
# MULTICHAIN END

            body += ['<tr><td><a href="../../' + escape(chain.name) + '/address/' + address + '">', address, '</a>',    # shorten via tx['hash'][:16]
                     '</td><td>', amount,
                     ' <a href="../../' + escape(chain.name) + '/assetaddress/' + address + '/' + assetref + '">(transactions)</a>',
                     '</td></tr>']

        body += ['</table>']



        # local method to get raw units for a given asset from a txin or txout,
        def get_asset_amount_from_txinout(tx, this_ch, other_ch, asset, chain):
            binaddr = tx['binaddr']
            if binaddr is None:
                return 0
            binscript = tx['binscript']
            if binscript is None:
                return 0
            # for input, we want to examine the txout it represents
            if this_ch=='i':
                binscript = tx['multichain_scriptPubKey']
            script_type, data = chain.parse_txout_script(binscript)
            if script_type not in [Chain.SCRIPT_TYPE_MULTICHAIN, Chain.SCRIPT_TYPE_MULTICHAIN_P2SH]:
                return 0
            data = util.get_multichain_op_drop_data(binscript)
            if data is None:
                return 0
            opdrop_type, val = util.parse_op_drop_data(data, chain)
            if opdrop_type==util.OP_DROP_TYPE_ISSUE_ASSET:
                return val
            elif opdrop_type==util.OP_DROP_TYPE_SEND_ASSET:
                for dict in val:
                    quantity = dict['quantity']
                    assetref = dict['assetref']
                    if assetref == asset['assetref']:
                        return quantity
            return 0


        # List any transactions for this asset

        body += ['<a name="transactions"><h3>Transactions</h3></a>\n']

        body += ['<table class="table table-striped"><tr>'
                 '<th>Transaction</th>'
                 '<th>Block</th>'
                 # '<th>Quantity Moved</th>'
                 '</tr>\n']

        transactions = abe.store.get_transactions_for_asset(chain, assetref)

        for tx in transactions:
            tx_hash = tx['hash']
            try:
                t = abe.store.export_tx(tx_hash = tx_hash, format = 'browser')
            except DataStore.MalformedHash:
                continue
            if t is None:
                continue

            out_amount = 0
            for txobj in t['out']:
                qty = get_asset_amount_from_txinout(txobj, 'o', 'i', asset, chain)
                out_amount = out_amount + qty
            # in_amount = 0
            # for txobj in t['in']:
            #     qty = get_asset_amount_from_txinout(txobj, 'i', 'o', asset, chain)
            #     in_amount = in_amount + qty

            # net_amount = in_amount - out_amount
            # net_amount_label = util.format_display_quantity(asset, net_amount)
            # if net_amount == 0:
            #     context = ""
            # elif net_amount > 0:
            #     context = "success"
            # else:
            #     context = "danger"

            # contextclass='class="' + context + '"'
            body += ['<tr><td><a href="../../' + escape(chain.name) + '/tx/' + tx['hash'] + '">', tx['hash'], '</a>',    # shorten via tx['hash'][:16]
                     '</td><td><a href="../../' + escape(chain.name) + '/block/', tx['blockhash'], '">', tx['height'], '</a>',
                     # '</td><td>', util.format_display_quantity(asset, in_amount),
                     # '</td><td>', util.format_display_quantity(asset, out_amount),
                     # '</td><td ' + contextclass +'>', net_amount_label,
                     '</td></tr>']
        body += ['</table>']


    # Page to show the assets that exist on a chain
    def handle_assets(abe, page):
        chain = page['chain']
        page['content_type'] = 'text/html'
        page['title'] = 'Assets of ' + chain.name
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)
        try:
            resp = util.jsonrpc(multichain_name, url, "listassets")
            num_assets = len(resp)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        if num_assets is 0:
            body += [ "No assets issued"]
            return

        body += ['<h3>Assets</h3>']

        body += ['<table class="table table-striped"><tr><th>Asset Name</th><th>Asset Reference</th>'
                 '<th>Issue Transaction</th>'
                 '<th>Asset Holders</th>'
                 '<th>Transactions</th>'
                 '<th>Issued Quantity</th><th>Units</th>'
                 '</tr>']

        unconfirmed = False
        for asset in resp:
            if asset['assetref'] is None:
                unconfirmed = True
                continue
            #details = ', '.join("{}={}".format(k,v) for (k,v) in asset['details'].iteritems())
            issueqty = util.format_display_quantity(asset, asset['issueraw'])
            holders = abe.store.get_number_of_asset_holders(chain, asset['assetref'])
            numtxs = abe.store.get_number_of_transactions_for_asset(chain, asset['assetref'])
            s = "{0:17f}".format(asset['units'])
            units = s.rstrip('0').rstrip('.') if '.' in s else s
            # handle anonymous assets
            assetname = asset.get('name','')
            body += ['<tr><td><a href="../../' + escape(chain.name) + '/assetref/' + asset['assetref'] + '">' + assetname.encode('unicode-escape') + '</a>',
                     '</td><td><a href="../../' + escape(chain.name) + '/assetref/' + asset['assetref'] + '">' + asset['assetref'] + '</a>',
                     '</td><td><a href="../../' + escape(chain.name) + '/tx/' + asset['issuetxid'] + '">',
                     asset['issuetxid'][:20], '...</a>',
                     '</td><td><a href="../../' + escape(chain.name) + '/assetref/' + asset['assetref'] + '#holders">', holders, '</a>',
                     '</td><td><a href="../../' + escape(chain.name) + '/assetref/' + asset['assetref'] + '#transactions">', numtxs, '</a>',
                     '</td><td>', issueqty,
                     '</td><td>', units,
                     '</td></tr>']

        body += ['</table>']

        # Show any unconfirmed assets
        if unconfirmed is False:
            return
        body += ['<h3>Unconfirmed Assets</h3>']

        body += ['<table class="table table-striped"><tr><th>Asset Name</th><th>Asset Reference</th>'
                 '<th>Issue Transaction</th>'
                 '<th>Asset Holders</th>'
                 '<th>Transactions</th>'
                 '<th>Issued Quantity</th><th>Units</th>'
                 '</tr>']
        for asset in resp:
            if asset['assetref'] is not None:
                continue
            issueqty = util.format_display_quantity(asset, asset['issueqty'])
            s = "{0:17f}".format(asset['units'])
            units = s.rstrip('0').rstrip('.') if '.' in s else s
            body += ['<tr><td>' + asset.get('name','').encode('unicode-escape'),
                     '</td><td>', '-',
                     '</td><td><a href="../../' + escape(chain.name) + '/mempooltx/' + asset['issuetxid'] + '">', asset['issuetxid'][:16], '...</a>',
                     '</td><td>', '-',
                     '</td><td>', '-',
                     '</td><td>', issueqty,
                     '</td><td>', units,
                     '</td></tr>']
        body += ['</table>']


    # Page to show the streams that exist on a chain
    def handle_streams(abe, page):
        chain = page['chain']

        page['content_type'] = 'text/html'
        page['title'] = 'Streams of ' + chain.name
        body = page['body']

        # url = abe.store.get_url_by_chain(chain)
        # multichain_name = abe.store.get_multichain_name_by_id(chain.id)
        try:
            resp = abe.store.list_streams(chain)
            num_streams = len(resp)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        if num_streams is 0:
            body += [ "No streams published"]
            return

        body += ['<h3>Streams</h3>']
        body += ['<table class="table table-striped">'
                 '<tr><th>Stream Name</th>'
                 '<th>Stream Items</th>'
                 '<th>Restrict</th>'
                 '<th>Creator</th>'
                 '<th>Creation Transaction</th>'
                 '</tr>']

        for stream in resp:
            #creators = '</br>'.join("{}".format(creator) for creator in stream['creators'])
            streamname = stream.get('name','')
            subscribed = stream['subscribed']
            if subscribed:
                streamitems_cell= '<a href="../../' + escape(chain.name) + '/streamitems/' + streamname + '">' + str(stream['items']) + '</a>'
            else:
                streamitems_cell = 'Not subscribed'

            if "restrict" in stream:
                restrict = stream["restrict"]
            else:
                restrict = {"write": stream["open"]}
            restrict_str = ','.join(k for k, v in restrict.items() if v)
            body += ['<tr><td><a href="../../' + escape(chain.name) + '/stream/' + streamname + '">' + streamname.encode('unicode-escape') + '</a>',
                     '</td><td>', streamitems_cell,
                     '</td><td>', restrict_str,
                     '</td><td><a href="../../' + escape(chain.name) + '/address/' + stream['creators'][0] + '">', stream['creators'][0], '</a>',
                     '</td><td><a href="../../' + escape(chain.name) + '/tx/' + stream['createtxid'] + '">',
                     stream['createtxid'][:20], '...</a>',
                     '</td></tr>']

        body += ['</table>']


    def handle_stream(abe, page):
        chain = page['chain']

        # Shift stream name
        streamname = wsgiref.util.shift_path_info(page['env'])
        if streamname in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = 'Stream'
        page['h1'] = 'Stream: <a href="../streams/">' + streamname + '</a>'
        body = page['body']

        try:
            resp = abe.store.list_stream(chain, streamname)
            publishers = abe.store.list_stream_publishers(chain, streamname)
            recentkeys = abe.store.list_stream_keys(chain, streamname)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return
        except Exception as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        if resp is None:
            body += ['<div class="alert alert-danger" role="warning">', 'liststreams did not return any data for stream' ,'</div>']
            return

        body += ['<h3>Summary</h3>']
        body += ['<table class="table table-bordered table-striped table-condensed">']
        for k,v in sorted(resp.items()):
            if k in ('confirmed', 'items'):
                v = '<a href="../../' + escape(chain.name) + '/streamitems/' + streamname + '">' + str(v) + '</a>'
            elif k in ('createtxid'):
                v = '<a href="../../' + escape(chain.name) + '/tx/' + v + '">' + v + '</a>'
            elif k in ('restrict'):
                v = ','.join(key for key, val in v.items() if val)
            body += html_keyvalue_tablerow_wrap(50, 300, k, v)
        body += ['</table>']

        body += ['<h3>Publishers</h3>']
        body += ['<table class="table table-striped"><tr>'
                 '<colgroup><col class="col-md-4"><col class="col-md-8"></colgroup>'
                 '<th>Publisher</th>'
                 '<th>Items</th>'
                 '</tr>\n']

       # body += ['<table class="table table-bordered table-striped table-condensed">']
        for publisher in publishers:
            address = publisher['publisher']
            publisher_link = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/publisheritems/' + streamname + '/' + address + '">' + address + '</a>'
            body += ['<tr><td>', publisher_link,
                     '</td><td>', str(publisher['items']),
                     '</td></tr>']
        body += ['</table>']

        body += ['<h3>Recently Updated Keys</h3>']
        body += ['<table class="table table-striped"><tr>'
                 '<colgroup><col class="col-md-4"><col class="col-md-8"></colgroup>'
                 '<th>Key</th>'
                 '<th>Number of Items</th>'
                 '</tr>\n']

        for obj in recentkeys:
            keylink = '<a href="' + page['dotdot'] + '/' + escape(chain.name)
            keylink += '/keyitems/' + streamname + '/' + obj['key'] + '">' + obj['key'] + '</a>'
            body += ['<tr><td>', keylink,
                     '</td><td>', str(obj['items']),
                     '</td></tr>']
        body += ['</table>']


    # Handle URL: base/chain/publisheritems/streamname/publisher
    def handle_publisheritems(abe, page):
        streamname = wsgiref.util.shift_path_info(page['env'])
        if streamname in (None, ''): # or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        publisher = wsgiref.util.shift_path_info(page['env'])
        if publisher in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        abe.do_streamitems(page, streamname, publisher)

    # Handle URL: base/chain/streamitems/streamname
    def handle_streamitems(abe, page):
        streamname = wsgiref.util.shift_path_info(page['env'])
        if streamname in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        abe.do_streamitems(page, streamname)

    def handle_keyitems(abe, page):
        streamname = wsgiref.util.shift_path_info(page['env'])
        if streamname in (None, ''): # or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        key = wsgiref.util.shift_path_info(page['env'])
        if key in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        abe.do_streamitems(page, streamname, None, key)


    def do_streamitems(abe, page, streamname, publisher = None, streamkey = None):
        chain = page['chain']

        page['title'] = 'Stream Items'
        page['h1'] = 'Stream: <a href="' + page['dotdot'] + '/' + escape(chain.name) + '/streams/">' + streamname + '</a>'
        body = page['body']

        # url = abe.store.get_url_by_chain(chain)
        # multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # url encoded parameters to control paging of items
        count = get_int_param(page, 'count') or 20
        hi = get_int_param(page, 'hi')

        try:
            resp = abe.store.list_stream(chain, streamname)
            if publisher is not None:
                resp2 = abe.store.list_stream_publishers(chain, streamname, publisher)
                num_publisher_items = resp2[0]['items']
            if streamkey is not None:
                resp3 = abe.store.list_stream_keys(chain, streamname, streamkey)
                num_filterkey_items = resp3[0]['items']
                if num_filterkey_items == 0:
                    msg = "Stream has no items for key '{0}'".format(streamkey)
                    body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
                    return
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return
        except IOError as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        mystream = resp

        if mystream is None:
            msg = "Stream '{0}' does not exist".format(streamname)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            return

        if publisher is not None:
            num_items = num_publisher_items
        elif streamkey is not None:
            num_items = num_filterkey_items
        else:
            num_items = mystream['items']


        if hi is None:
            hi = num_items

        # check to make sure hi is not too high
        if hi > num_items:
            hi = num_items


        if publisher is not None:
            body += ['<h3>Items Published By: ' + publisher + '</h3>']
        elif streamkey is not None:
            body += ['<h3>Items For Key: ' + streamkey + '</h3>']
        else:
            body += ['<h3>Stream Items</h3>']


        createtxid = mystream['createtxid']
        try:
            if publisher is not None:
                streamitems = abe.store.list_stream_publisher_items(chain, createtxid, publisher, count, max( hi - count, 0) )
            elif streamkey is not None:
                streamitems = abe.store.list_stream_key_items(chain, createtxid, streamkey, count, max(hi - count, 0))
            else:
                streamitems = abe.store.list_stream_items(chain, createtxid, count, max( hi - count, 0) ) # 0 if remainder is less than count
        except Exception as e:
            body += ['<div class="alert alert-danger" role="warning">', e ,'</div>']
            return

        # timestamp, publisher key, data (link to raw data), txid,

        basename = os.path.basename(page['env']['PATH_INFO'])

        nav = ['<a href="',
               basename, '?count=', str(count), '">&lt;&lt;</a>']
        nav += [' <a href="', basename, '?hi=', str(hi + count),
                 '&amp;count=', str(count), '">&lt;</a>']
        nav += [' ', '&gt;']
        if hi >= count:
            nav[-1] = ['<a href="', basename, '?hi=', str(hi - count),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        nav += [' ', '&gt;&gt;']
        if hi != count - 1:
            nav[-1] = ['<a href="', basename, '?hi=', str(count - 1),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        for c in (20, 50, 100, 500):
            nav += [' ']
            if c != count:
                nav += ['<a href="', basename, '?count=', str(c)]
                if hi is not None:
                    nav += ['&amp;hi=', str(max(hi, c - 1))]
                nav += ['">']
            nav += [' ', str(c)]
            if c != count:
                nav += ['</a>']

        #nav += [' <a href="', page['dotdot'], '">Search</a>']

        body += ['<p>', nav, '</p>\n',
                 '<table class="table table-striped"><tr>'
                 '<th>Time</th>'
                 '<th>Key</th>'
                 '<th>Value</th>'
                 # '<th>Raw Data</th>',
                 '<th>Publisher</th>'
                 '<th>Transaction</th>'
                 '</tr>\n']

        # sort streamitems in descending order, so most recent timestamp is at top of page
        sorted_streamitems = sorted(streamitems, key=lambda item: item['time'], reverse=True)


        for item in sorted_streamitems:

            if len(item['publishers'])==1:
                publisher = item['publishers'][0]
                publisher_address = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/publisheritems/' + streamname + '/' + publisher + '">' + publisher + '</a>'
            else:
                publisher_address = ''
                for publisher in item['publishers']:
                    publisher_link = '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/publisheritems/' + streamname + '/' + publisher + '">' + publisher + '</a>'
                    publisher_address += '{0}<br/>'.format(publisher_link)

            # A runtime paramater -maxshowndata=20 determines if the node returns data in json output or not.
            # The node itself will not store more than 256 bytes of data.  The blockchain database stores all dadta.
            # If the length of the data is > maxshowndata, instead of hex data you receieve:
            # "data" : {
            #  "txid" : "7b9a6e1b948e426e82d0fd94b1686c301516ce0fd9522a2f8189cd52c046bd62",
            #  "vout" : 0,
            #  "size" : 576
            # }
            txid = item['txid']  # data['txid'] should be the same
            data = item['data']
            vout = item['vout']
            size = 0
            printdata = False
            mydata = None
            if type(data) is dict:
                if 'text' in data:
                    mydata = data['text']
                    printdata = True
                elif 'json' in data:
                    mydata = json.dumps(data['json'])
                    printdata = True
                else:
                    mydata = 'Too large to show'
                    vout = data['vout']
                    size = data['size']
            else:
                mydata = data
                size = len(data) / 2

                # try to decode hex data as ascii, and also check length
                try:
                    ascdata = binascii.unhexlify(data)
                    if util.is_printable(ascdata) is True:
                        mydata = ascdata
                        printdata = True
                    # else:
                    #     mydata = 'Binary data'
                except UnicodeDecodeError:
                    numchars = 20
                    mydata = data[:numchars * 2]
                    if len(data) > numchars:
                        mydata += '... '
                    printdata = True

            data_ref = '{}/{}/txoutdata/{}/{}'.format(page['dotdot'], escape(chain.name), txid, vout)
            sizelink ='<a href="' + data_ref + '">' + str(size) + ' bytes</a>'

            if printdata:
                data_html = util.render_long_data_with_popover(mydata)
                # data_html = mydata
            else:
                data_html = util.render_long_data_with_link(mydata, data_ref, limit=20)
                # data_html = ['<em>', mydata, '</em>']

            blocktime = int(item.get('blocktime', -1))
            if blocktime == -1:
                timestamp_label = 'Unconfirmed'
            else:
                timestamp_label = format_time(blocktime)

            # Get keys for the item
            keys = []
            if chain.protocol_version < 20001:  # Older protocols have only one key
                keys = [item['key']]
            else:  # Get all keys
                keys = item['keys']

            # Create a list of key links
            prefix = '{}/{}/keyitems/{}'.format(page['dotdot'], escape(chain.name), streamname)
            keylinks = ['<a href="{0}/{1}">{1}</a>'.format(prefix, key) for key in keys]
            keyshtml = ', '.join(keylinks)
            # If list is too long, display only first few keys, and enable a popover with the full list
            key_limit = 5
            if len(keylinks) >= key_limit:
                keyshtml = '{}, <span class="ellipses" data-toggle="popover" data-content="{}">...</span>'.format(
                    ', '.join(keylinks[:key_limit]), escape(', '.join(keylinks), quote=True))

            body += [
                '<tr>'
                '</td><td>', timestamp_label,
                '</td><td>', keyshtml,
                '</td><td>', data_html,
                # '</td><td>', sizelink,
                '</td><td>', publisher_address,
                '</td><td>', '<a href="' + page['dotdot'] + '/' + escape(chain.name) + '/tx/' + txid + '">', txid[0:10], '...</a>',
                '</td></tr>\n']

        body += ['</table>\n<p>', nav, '</p>\n']


    def handle_txoutdata(abe, page):
        abe.do_rpc(page, abe.do_rpc_txoutdata)

    def do_rpc_txoutdata(abe, page, chain):
        chain = page['chain']

        # Shift txid
        txid = wsgiref.util.shift_path_info(page['env'])
        if txid in (None, ''): # or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        # Shift vout
        vout = wsgiref.util.shift_path_info(page['env'])
        if vout in (None, '') or page['env']['PATH_INFO'] != '':
             raise PageNotFound()

        page['title'] = 'Data for ' + txid + ' vout ' + vout
        body = page['body']

        chain_name = abe.store.get_multichain_name_by_id(chain.id)
        url = abe.store.get_url_by_chain(chain)

        try:
            resp = util.jsonrpc(chain_name, url, "gettxoutdata", txid, int(vout))
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            #if e.code != -5:  # -5: transaction not in index.
            s = '<div class="alert alert-danger" role="warning">' + msg + '</div>'
            page['content_type'] = 'text/html'
            return s
        except IOError as e:
            msg= "I/O error({0}): {1}".format(e.errno, e.strerror)
            s = '<div class="alert alert-danger" role="alert">' + msg + '</div>'
            page['title'] = 'IO ERROR'
            page['content_type'] = 'text/html'
            return s

        s = resp

        # this removes the standard html template, we are ok returning text now, no error.
        page['template'] = '%(body)s'

        return s


    # Experimental handler for getting json and raw hex data from RPC calls
    def do_rpc(abe, page, func):
        page['content_type'] = 'text/plain; charset="UTF-8"'

        # this removes the standard html template
        #page['template'] = '%(body)s'

        page['body'] = func(page, page['chain'])

    def handle_rpctxjson(abe, page):
        page['decode_json']=True
        abe.do_rpc(page, abe.do_rpc_tx)

    def handle_rpctxraw(abe, page):
        abe.do_rpc(page, abe.do_rpc_tx)

    def do_rpc_tx(abe, page, chain):
        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '' \
                or not is_hash_prefix(tx_hash):
            return 'ERROR: Not in correct format'  # BBE compatible

        tx = abe.store.export_tx(tx_hash=tx_hash.lower(), format='browser')
        if tx is None:
            return 'ERROR: Transaction does not exist.'  # BBE compatible

        decode_json_flag = 0
        if page.get('decode_json', False) is True:
            decode_json_flag = 1

        chain = None
        for tx_cc in tx['chain_candidates']:
            if chain is None:
                chain = tx_cc['chain']
                is_coinbase = (tx_cc['tx_pos'] == 0)
            elif tx_cc['chain'].id != chain.id:
                abe.log.warning('Transaction ' + tx['hash'] + ' in multiple chains: '
                             + tx_cc['chain'].id + ', ' + chain.id)

        chain_name = abe.store.get_multichain_name_by_id(chain.id)
        url = abe.store.get_url_by_chain(chain)

        s = ""
        # s = ("chain: %r" % chain)
        # s += "\nchain.name = %s" % chain.name
        # s += "\nchain.code3 = %s" % chain.code3
        # s += "\nchain.id = %s" % chain.id
        # s += "\nchain.datadir_conf_file_name = %s" % chain.datadir_conf_file_name
        # s += "\nchain_name = %s" % chain_name
        # s += "\nurl = %s" % url

        try:
            resp = util.jsonrpc(chain_name, url, "getrawtransaction", tx_hash, decode_json_flag)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            #if e.code != -5:  # -5: transaction not in index.
            s = '<div class="alert alert-danger" role="warning">' + msg + '</div>'
            page['content_type'] = 'text/html'
            return s
        except IOError as e:
            msg= "I/O error({0}): {1}".format(e.errno, e.strerror)
            s = '<div class="alert alert-danger" role="alert">' + msg + '</div>'
            page['title'] = 'IO ERROR'
            page['content_type'] = 'text/html'
            return s

        if decode_json_flag is 1:
            s = json.dumps(resp, sort_keys=True, indent=2)
        else:
            s = resp

        # this removes the standard html template, we are ok returning text now, no error.
        page['template'] = '%(body)s'

        return s

    def handle_mempooltx(abe, page):
        page['content_type'] = 'text/html'
        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = ['Transaction ', tx_hash[:10], '...', tx_hash[-4:]]
        body = page['body']

        chain = page['chain']
        chain_name = abe.store.get_multichain_name_by_id(chain.id)
        url = abe.store.get_url_by_chain(chain)

        s=""
        try:
            resp = util.jsonrpc(chain_name, url, "getrawtransaction", tx_hash, 1)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            #if e.code != -5:  # -5: transaction not in index.
            body += '<div class="alert alert-danger" role="warning">' + msg + '</div>'
            return s
        except IOError as e:
            msg= "I/O error({0}): {1}".format(e.errno, e.strerror)
            body += '<div class="alert alert-danger" role="alert">' + msg + '</div>'
            return s

        return abe.show_mempool_tx_json(page, resp)
        
# MULTICHAIN END

    def do_rawtx(abe, page, chain):
        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '' \
                or not is_hash_prefix(tx_hash):
            return 'ERROR: Not in correct format'  # BBE compatible

        tx = abe.store.export_tx(tx_hash=tx_hash.lower())
        if tx is None:
            return 'ERROR: Transaction does not exist.'  # BBE compatible
        return json.dumps(tx, sort_keys=True, indent=2)

    def handle_deprecatedaddress(abe, page):
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        body = page['body']
        page['title'] = 'Address ' + escape(address)

        try:
            history = abe.store.export_address_history(
                address, chain=page['chain'], max_rows=abe.address_history_rows_max)
        except DataStore.MalformedAddress:
            page['status'] = '404 Not Found'
            body += ['<p>Not a valid address.</p>']
            return

        if history is None:
            body += ["<p>I'm sorry, this address has too many records"
                     " to display.</p>"]
            return

        binaddr  = history['binaddr']
        version  = history['version']
        chains   = history['chains']
        txpoints = history['txpoints']
        balance  = history['balance']
        sent     = history['sent']
        received = history['received']
        counts   = history['counts']

        if (not chains):
            page['status'] = '404 Not Found'
# MULTICHAIN START
            body += ['<p>Address not seen on the blockchain.</p>']
# MULTICHAIN END
            return

        def format_amounts(amounts, link):
            ret = []
            for chain in chains:
                if ret:
                    ret += [', ']
                ret += [format_satoshis(amounts[chain.id], chain),
                        ' ', escape(chain.code3)]
                if link:
                    vers = chain.address_version
                    if page['chain'] is not None and version == page['chain'].script_addr_vers:
                        vers = chain.script_addr_vers or vers
# MULTICHAIN START
                    checksum = chain.address_checksum
                    if checksum is None:
                        other = util.hash_to_address(vers, binaddr)
                    else:
                        other = util.hash_to_address_multichain(vers, binaddr, checksum)
# MULTICHAIN END
                    if other != address:
                        ret[-1] = ['<a href="', page['dotdot'],
                                   'address/', other,
                                   '">', ret[-1], '</a>']
            return ret

        if abe.shortlink_type == "firstbits":
            link = abe.store.get_firstbits(
                address_version=version, db_pubkey_hash=abe.store.binin(binaddr),
                chain_id = (page['chain'] and page['chain'].id))
            if link:
                link = link.replace('l', 'L')
            else:
                link = address
        else:
            link = address[0 : abe.shortlink_type]
# MULTICHAIN START
        # body += abe.short_link(page, 'a/' + link)
        body += ['<table class="table-bordered table-condensed">']

        body += html_keyvalue_tablerow('Balance', format_amounts(balance, True))
# MULTICHAIN END

        if 'subbinaddr' in history:
            chain = page['chain']

            if chain is None:
                for c in chains:
                    if c.script_addr_vers == version:
                        chain = c
                        break
                if chain is None:
                    chain = chains[0]
# MULTICHAIN START
            tmp = []
            for subbinaddr in history['subbinaddr']:
                tmp += [' ', hash_to_address_link(chain.address_version, subbinaddr, page['dotdot'], 10) ]
            body += html_keyvalue_tablerow('Escrow', tmp)
# MULTICHAIN END

        for chain in chains:
            balance[chain.id] = 0  # Reset for history traversal.
# MULTICHAIN START
        body += html_keyvalue_tablerow('Transactions in' , counts[0])
        body += html_keyvalue_tablerow('Received', format_amounts(received, False))
        body += html_keyvalue_tablerow('Transactions out', counts[1])
        body += html_keyvalue_tablerow('Sent', format_amounts(sent, False))
        body += ['</table>']

        body += [
                 '<h3>Transactions</h3>\n'
                 '<table class="table table-striped">\n<tr><th>Transaction</th><th>Block</th>'
# MULTICHAIN END
                 '<th>Approx. Time</th><th>Amount</th><th>Balance</th>'
                 '<th>Currency</th></tr>\n']

        for elt in txpoints:
            chain = elt['chain']
            type = elt['type']

            if type == 'direct':
                balance[chain.id] += elt['value']

            body += ['<tr class="', type, '"><td class="tx"><a href="../tx/', elt['tx_hash'],
                     '#', 'i' if elt['is_out'] else 'o', elt['pos'],
                     '">', elt['tx_hash'][:10], '...</a>',
                     '</td><td class="block"><a href="../block/', elt['blk_hash'],
                     '">', elt['height'], '</a></td><td class="time">',
                     format_time(elt['nTime']), '</td><td class="amount">']

            if elt['value'] < 0:
                value = '(' + format_satoshis(-elt['value'], chain) + ')'
            else:
                value = format_satoshis(elt['value'], chain)

            if 'binaddr' in elt:
# MULTICHAIN START
                value = hash_to_address_link(chain.script_addr_vers, elt['binaddr'], page['dotdot'], text=value)
# MULTICHAIN END
            body += [value, '</td><td class="balance">',
                     format_satoshis(balance[chain.id], chain),
                     '</td><td class="currency">', escape(chain.code3),
                     '</td></tr>\n']
        body += ['</table>\n']

    def search_form(abe, page):
        q = (page['params'].get('q') or [''])[0]
        return [
# MULTICHAIN START
            '<p>Search by address, block number or hash, transaction or'
            ' chain name:</label></p>'
            '<form class="form-inline" action="', page['dotdot'], 'search"><p>\n'
            '<div class="form-group">'
            '<input id="search1" type="text" name="q" size="64" value="', escape(q), '" style="height: 32px; margin-right: 10px;"/>'
            '<button type="submit" class="btn" style="height: 32px; vertical-align: middle;">Search</button>\n'
            '<p class="help-block">Address or hash search requires at least the first ',
            HASH_PREFIX_MIN, ' characters.</p></div></form>\n']
# MULTICHAIN END

    def handle_search(abe, page):
        page['title'] = 'Search'
        q = (page['params'].get('q') or [''])[0]
# MULTICHAIN START
        q = q.strip()
        q = q.decode("utf-8")
        page['chain'] = abe.store.get_chain_by_id(1)
# MULTICHAIN END
        if q == '':
            page['body'] = [
                '<p>Please enter search terms.</p>\n', abe.search_form(page)]
            return

        found = []
        if HEIGHT_RE.match(q):      found += abe.search_number(int(q))
        if util.possible_address(q):found += abe.search_address(q)
        elif ADDR_PREFIX_RE.match(q):found += abe.search_address_prefix(q)
# MULTICHAIN START
        if is_hash_prefix(q):       found += abe.search_hash_prefix(q, types = ('tx', 'block'))
# MULTICHAIN END
        found += abe.search_general(q)
        abe.show_search_results(page, found)

    def show_search_results(abe, page, found):
        if not found:
            page['body'] = [
                '<p>No results found.</p>\n', abe.search_form(page)]
            return

# MULTICHAIN START
        chain_name = escape(page['chain'].name)
        newfound = []
        for x in found:
            x['uri'] = chain_name + '/' + x['uri']
            newfound.append(x)
        found = newfound
# MULTICHAIN END

        if len(found) == 1:
            # Undo shift_path_info.
            sn = posixpath.dirname(page['env']['SCRIPT_NAME'])
            if sn == '/': sn = ''
            page['env']['SCRIPT_NAME'] = sn
            page['env']['PATH_INFO'] = '/' + page['dotdot'] + found[0]['uri']
            del(page['env']['QUERY_STRING'])
            raise Redirect()

        body = page['body']
        body += ['<h3>Search Results</h3>\n<ul>\n']
        for result in found:
            body += [
                '<li><a href="', page['dotdot'], escape(result['uri']), '">',
                escape(result['name']), '</a></li>\n']
        body += ['</ul>\n']

    def search_number(abe, n):
        def process(row):
            (chain_name, dbhash, in_longest) = row
            hexhash = abe.store.hashout_hex(dbhash)
            if in_longest == 1:
                name = str(n)
            else:
                name = hexhash
            return {
                'name': chain_name + ' ' + name,
                'uri': 'block/' + hexhash,
                }

        return map(process, abe.store.selectall("""
            SELECT c.chain_name, b.block_hash, cc.in_longest
              FROM chain c
              JOIN chain_candidate cc ON (cc.chain_id = c.chain_id)
              JOIN block b ON (b.block_id = cc.block_id)
             WHERE cc.block_height = ?
             ORDER BY c.chain_name, cc.in_longest DESC
        """, (n,)))

    def search_hash_prefix(abe, q, types = ('tx', 'block', 'pubkey')):
        q = q.lower()
        ret = []
        for t in types:
            def process(row):
                if   t == 'tx':    name = 'Transaction'
                elif t == 'block': name = 'Block'
                else:
                    # XXX Use Bitcoin address version until we implement
                    # /pubkey/... for this to link to.
                    return abe._found_address(
                        util.hash_to_address('\0', abe.store.binout(row[0])))
                hash = abe.store.hashout_hex(row[0])
                return {
                    'name': name + ' ' + hash,
                    'uri': t + '/' + hash,
                    }

            if t == 'pubkey':
                if len(q) > 40:
                    continue
                lo = abe.store.binin_hex(q + '0' * (40 - len(q)))
                hi = abe.store.binin_hex(q + 'f' * (40 - len(q)))
            else:
                lo = abe.store.hashin_hex(q + '0' * (64 - len(q)))
                hi = abe.store.hashin_hex(q + 'f' * (64 - len(q)))

            ret += map(process, abe.store.selectall(
                "SELECT " + t + "_hash FROM " + t + " WHERE " + t +
                # XXX hardcoded limit.
                "_hash BETWEEN ? AND ? LIMIT 100",
                (lo, hi)))
        return ret

    def _found_address(abe, address):
# MULTICHAIN START
        return { 'name': 'Address ' + address, 'uri': 'address/' + address }
# MULTICHAIN END

    def search_address(abe, address):
        try:
# MULTICHAIN START
            # Only search the first chain for now
            chain = abe.store.get_chain_by_id(1)
            version, binaddr = util.decode_check_address_multichain(address)
# MULTICHAIN END
        except Exception:
            return abe.search_address_prefix(address)
        return [abe._found_address(address)]

# MULTICHAIN START
    def search_address_prefix(abe, ap):
        """
        Naive method to search for an address.
        :param ap: string containing first few characters of an address
        :return: list of matches
        """

        ret = []

        # Only search the first chain for now
        chain = abe.store.get_chain_by_id(1)
        address_version = chain.address_version
        checksum = chain.address_checksum

        def process(row):
            hash = abe.store.binout(row[0])
            if hash is None:
                return None
            address = util.hash_to_address_multichain(address_version, hash, checksum)
            if not address.lower().startswith(ap.lower()):
                return None
            return abe._found_address(address)

        ret += filter(None, map(process, abe.store.selectall("SELECT pubkey_hash FROM pubkey" )))
        return ret
# MULTICHAIN END

    def DEPRECATED_search_address_prefix(abe, ap):
        ret = []
        ones = 0
        for c in ap:
            if c != '1':
                break
            ones += 1
        all_ones = (ones == len(ap))
        minlen = max(len(ap), 24)
        l = max(35, len(ap))  # XXX Increase "35" to support multibyte
                              # address versions.
        al = ap + ('1' * (l - len(ap)))
        ah = ap + ('z' * (l - len(ap)))

        def incr_str(s):
            for i in range(len(s)-1, -1, -1):
                if s[i] != '\xff':
                    return s[:i] + chr(ord(s[i])+1) + ('\0' * (len(s) - i - 1))
            return '\1' + ('\0' * len(s))

        def process(row):
            hash = abe.store.binout(row[0])
            address = util.hash_to_address(vl, hash)
            if address.startswith(ap):
                v = vl
            else:
                if vh != vl:
                    address = util.hash_to_address(vh, hash)
                    if not address.startswith(ap):
                        return None
                    v = vh
            if abe.is_address_version(v):
                return abe._found_address(address)

        while l >= minlen:
            vl, hl = util.decode_address(al)
            vh, hh = util.decode_address(ah)
            if ones:
                if not all_ones and \
                        util.hash_to_address('\0', hh)[ones:][:1] == '1':
                    break
            elif vh == '\0':
                break
            elif vh != vl and vh != incr_str(vl):
                continue
            if hl <= hh:
                neg = ""
            else:
                neg = " NOT"
                hl, hh = hh, hl
            bl = abe.store.binin(hl)
            bh = abe.store.binin(hh)
            ret += filter(None, map(process, abe.store.selectall(
                "SELECT pubkey_hash FROM pubkey WHERE pubkey_hash" +
                # XXX hardcoded limit.
                neg + " BETWEEN ? AND ? LIMIT 100", (bl, bh))))
            l -= 1
            al = al[:-1]
            ah = ah[:-1]

        return ret

    def search_general(abe, q):
        """Search for something that is not an address, hash, or block number.
        Currently, this is limited to chain names and currency codes."""
        def process(row):
            (name, code3) = row
            return { 'name': name + ' (' + code3 + ')',
                     'uri': 'chain/' + str(name) }
        ret = map(process, abe.store.selectall("""
            SELECT chain_name, chain_code3
              FROM chain
             WHERE UPPER(chain_name) LIKE '%' || ? || '%'
                OR UPPER(chain_code3) LIKE '%' || ? || '%'
        """, (q.upper(), q.upper())))
        return ret

    def handle_t(abe, page):
        abe.show_search_results(
            page,
            abe.search_hash_prefix(
                b58hex(wsgiref.util.shift_path_info(page['env'])),
                ('tx',)))

    def handle_b(abe, page):
        if page.get('chain') is not None:
            chain = page['chain']
            height = wsgiref.util.shift_path_info(page['env'])
            try:
                height = int(height)
            except Exception:
                raise PageNotFound()
            if height < 0 or page['env']['PATH_INFO'] != '':
                raise PageNotFound()

            cmd = wsgiref.util.shift_path_info(page['env'])
            if cmd is not None:
                raise PageNotFound()  # XXX want to support /a/...

            page['title'] = [escape(chain.name), ' ', height]
            abe._show_block(page, page['dotdot'] + 'block/', chain, block_number=height)
            return

        abe.show_search_results(
            page,
            abe.search_hash_prefix(
                shortlink_block(wsgiref.util.shift_path_info(page['env'])),
                ('block',)))

    def handle_a(abe, page):
        arg = wsgiref.util.shift_path_info(page['env'])
        if abe.shortlink_type == "firstbits":
            addrs = map(
                abe._found_address,
                abe.store.firstbits_to_addresses(
                    arg.lower(),
                    chain_id = page['chain'] and page['chain'].id))
        else:
            addrs = abe.search_address_prefix(arg)
        abe.show_search_results(page, addrs)

    def handle_unspent(abe, page):
        abe.do_raw(page, abe.do_unspent)

    def do_unspent(abe, page, chain):
        addrs = wsgiref.util.shift_path_info(page['env'])
        if addrs is None:
            addrs = []
        else:
            addrs = addrs.split("|")
        if len(addrs) < 1 or len(addrs) > MAX_UNSPENT_ADDRESSES:
            return 'Number of addresses must be between 1 and ' + \
                str(MAX_UNSPENT_ADDRESSES)

        if chain:
            chain_id = chain.id
            bind = [chain_id]
        else:
            chain_id = None
            bind = []

        hashes = []
        good_addrs = []
        for address in addrs:
            try:
                hashes.append(abe.store.binin(
                        base58.bc_address_to_hash_160(address)))
                good_addrs.append(address)
            except Exception:
                pass
        addrs = good_addrs
        bind += hashes

        if len(hashes) == 0:  # Address(es) are invalid.
            return 'Error getting unspent outputs'  # blockchain.info compatible

        placeholders = "?" + (",?" * (len(hashes)-1))

        max_rows = abe.address_history_rows_max
        if max_rows >= 0:
            bind += [max_rows + 1]

        spent = set()
        for txout_id, spent_chain_id in abe.store.selectall("""
            SELECT txin.txout_id, cc.chain_id
              FROM chain_candidate cc
              JOIN block_tx ON (block_tx.block_id = cc.block_id)
              JOIN txin ON (txin.tx_id = block_tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE cc.in_longest = 1""" + ("" if chain_id is None else """
               AND cc.chain_id = ?""") + """
               AND pubkey.pubkey_hash IN (""" + placeholders + """)""" + (
                "" if max_rows < 0 else """
             LIMIT ?"""), bind):
            spent.add((int(txout_id), int(spent_chain_id)))

        abe.log.debug('spent: %s', spent)

        received_rows = abe.store.selectall("""
            SELECT
                txout.txout_id,
                cc.chain_id,
                tx.tx_hash,
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                cc.block_height
              FROM chain_candidate cc
              JOIN block_tx ON (block_tx.block_id = cc.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE cc.in_longest = 1""" + ("" if chain_id is None else """
               AND cc.chain_id = ?""") + """
               AND pubkey.pubkey_hash IN (""" + placeholders + """)""" + (
                "" if max_rows < 0 else """
             ORDER BY cc.block_height,
                   block_tx.tx_pos,
                   txout.txout_pos
             LIMIT ?"""), bind)

        if 0 <= max_rows < len(received_rows):
            return "ERROR: too many records to process"

        rows = []
        for row in received_rows:
            key = (int(row[0]), int(row[1]))
            if key in spent:
                continue
            rows.append(row[2:])

        if len(rows) == 0:
            return 'No free outputs to spend [' + '|'.join(addrs) + ']'

        out = []
        for row in rows:
            tx_hash, out_pos, script, value, height = row
            tx_hash = abe.store.hashout_hex(tx_hash)
            out_pos = None if out_pos is None else int(out_pos)
            script = abe.store.binout_hex(script)
            value = None if value is None else int(value)
            height = None if height is None else int(height)
            out.append({
                    'tx_hash': tx_hash,
                    'tx_output_n': out_pos,
                    'script': script,
                    'value': value,
                    'value_hex': None if value is None else "%x" % value,
                    'block_number': height})

        return json.dumps({ 'unspent_outputs': out }, sort_keys=True, indent=2)

    def do_raw(abe, page, func):
        page['content_type'] = 'text/plain'
        page['template'] = '%(body)s'
        page['body'] = func(page, page['chain'])

    def handle_q(abe, page):
        cmd = wsgiref.util.shift_path_info(page['env'])
        if cmd is None:
            return abe.q(page)

        func = getattr(abe, 'q_' + cmd, None)
        if func is None:
            raise PageNotFound()

        abe.do_raw(page, func)

        if page['content_type'] == 'text/plain':
            jsonp = page['params'].get('jsonp', [None])[0]
            fmt = page['params'].get('format', ["jsonp" if jsonp else "csv"])[0]

            if fmt in ("json", "jsonp"):
                page['body'] = json.dumps([page['body']])

                if fmt == "jsonp":
                    page['body'] = (jsonp or "jsonp") + "(" + page['body'] + ")"
                    page['content_type'] = 'application/javascript'
                else:
                    page['content_type'] = 'application/json'

    def q(abe, page):
        page['body'] = ['<p>Supported APIs:</p>\n<ul>\n']
        for name in dir(abe):
            if not name.startswith("q_"):
                continue
            cmd = name[2:]
            page['body'] += ['<li><a href="q/', cmd, '">', cmd, '</a>']
            val = getattr(abe, name)
            if val.__doc__ is not None:
                page['body'] += [' - ', escape(val.__doc__)]
            page['body'] += ['</li>\n']
        page['body'] += ['</ul>\n']

    def get_max_block_height(abe, chain):
        # "getblockcount" traditionally returns max(block_height),
        # which is one less than the actual block count.
        return abe.store.get_block_number(chain.id)

    def q_getblockcount(abe, page, chain):
        """shows the current block number."""
        if chain is None:
            return 'Shows the greatest block height in CHAIN.\n' \
                '/chain/CHAIN/q/getblockcount\n'
        return abe.get_max_block_height(chain)

    def q_getdifficulty(abe, page, chain):
        """shows the last solved block's difficulty."""
        if chain is None:
            return 'Shows the difficulty of the last block in CHAIN.\n' \
                '/chain/CHAIN/q/getdifficulty\n'
        target = abe.store.get_target(chain.id)
        return "" if target is None else util.target_to_difficulty(target)

    def q_translate_address(abe, page, chain):
        """shows the address in a given chain with a given address's hash."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'Translates ADDRESS for use in CHAIN.\n' \
                '/chain/CHAIN/q/translate_address/ADDRESS\n'
# MULTICHAIN START
        version, hash = util.decode_check_address_multichain(addr)
# MULTICHAIN END
        if hash is None:
            return addr + " (INVALID ADDRESS)"
        return util.hash_to_address(chain.address_version, hash)

    def q_decode_address(abe, page, chain):
        """shows the version prefix and hash encoded in an address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return "Shows ADDRESS's version byte(s) and public key hash" \
                ' as hex strings separated by colon (":").\n' \
                '/q/decode_address/ADDRESS\n'
        # XXX error check?
        version, hash = util.decode_address(addr)
        ret = version.encode('hex') + ":" + hash.encode('hex')
        if util.hash_to_address(version, hash) != addr:
            ret = "INVALID(" + ret + ")"
        return ret

    def q_addresstohash(abe, page, chain):
        """shows the public key hash encoded in an address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return 'Shows the 160-bit hash encoded in ADDRESS.\n' \
                'For BBE compatibility, the address is not checked for' \
                ' validity.  See also /q/decode_address.\n' \
                '/q/addresstohash/ADDRESS\n'
        version, hash = util.decode_address(addr)
        return hash.encode('hex').upper()

    def q_hashtoaddress(abe, page, chain):
        """shows the address with the given version prefix and hash."""
        arg1 = wsgiref.util.shift_path_info(page['env'])
        arg2 = wsgiref.util.shift_path_info(page['env'])
        if arg1 is None:
            return \
                'Converts a 160-bit hash and address version to an address.\n' \
                '/q/hashtoaddress/HASH[/VERSION]\n'

        if page['env']['PATH_INFO']:
            return "ERROR: Too many arguments"

        if arg2 is not None:
            # BBE-compatible HASH/VERSION
            version, hash = arg2, arg1

        elif arg1.find(":") >= 0:
            # VERSION:HASH as returned by /q/decode_address.
            version, hash = arg1.split(":", 1)

        elif chain:
            version, hash = chain.address_version.encode('hex'), arg1

        else:
            # Default: Bitcoin address starting with "1".
            version, hash = '00', arg1

        try:
            hash = hash.decode('hex')
            version = version.decode('hex')
        except Exception:
            return 'ERROR: Arguments must be hexadecimal strings of even length'
        return util.hash_to_address(version, hash)

    def q_hashpubkey(abe, page, chain):
        """shows the 160-bit hash of the given public key."""
        pubkey = wsgiref.util.shift_path_info(page['env'])
        if pubkey is None:
            return \
                "Returns the 160-bit hash of PUBKEY.\n" \
                "For example, the Bitcoin genesis block's output public key," \
                " seen in its transaction output scriptPubKey, starts with\n" \
                "04678afdb0fe..., and its hash is" \
                " 62E907B15CBF27D5425399EBF6F0FB50EBB88F18, corresponding" \
                " to address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.\n" \
                "/q/hashpubkey/PUBKEY\n"
        try:
            pubkey = pubkey.decode('hex')
        except Exception:
            return 'ERROR: invalid hexadecimal byte string.'
        return util.pubkey_to_hash(pubkey).encode('hex').upper()

    def q_checkaddress(abe, page, chain):
        """checks an address for validity."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return \
                "Returns the version encoded in ADDRESS as a hex string.\n" \
                "If ADDRESS is invalid, returns either X5, SZ, or CK for" \
                " BBE compatibility.\n" \
                "/q/checkaddress/ADDRESS\n"
        if util.possible_address(addr):
            version, hash = util.decode_address(addr)
            if util.hash_to_address(version, hash) == addr:
                return version.encode('hex').upper()
            return 'CK'
        if len(addr) >= 26:
            return 'X5'
        return 'SZ'

    def q_nethash(abe, page, chain):
        """shows statistics about difficulty and network power."""
        if chain is None:
            return 'Shows statistics every INTERVAL blocks.\n' \
                'Negative values count back from the last block.\n' \
                '/chain/CHAIN/q/nethash[/INTERVAL[/START[/STOP]]]\n'

        jsonp = page['params'].get('jsonp', [None])[0]
        fmt = page['params'].get('format', ["jsonp" if jsonp else "csv"])[0]
        interval = path_info_int(page, 144)
        start = path_info_int(page, 0)
        stop = path_info_int(page, None)

        if stop == 0:
            stop = None

        if interval < 0 and start != 0:
            return 'ERROR: Negative INTERVAL requires 0 START.'

        if interval < 0 or start < 0 or (stop is not None and stop < 0):
            count = abe.get_max_block_height(chain)
            if start < 0:
                start += count
            if stop is not None and stop < 0:
                stop += count
            if interval < 0:
                interval = -interval
                start = count - (count / interval) * interval

        # Select every INTERVAL blocks from START to STOP.
        # Standard SQL lacks an "every Nth row" feature, so we
        # provide it with the help of a table containing the integers.
        # We don't need all integers, only as many as rows we want to
        # fetch.  We happen to have a table with the desired integers,
        # namely chain_candidate; its block_height column covers the
        # required range without duplicates if properly constrained.
        # That is the story of the second JOIN.

        if stop is not None:
            stop_ix = (stop - start) / interval

        rows = abe.store.selectall("""
            SELECT b.block_height,
                   b.block_nTime,
                   b.block_chain_work,
                   b.block_nBits
              FROM block b
              JOIN chain_candidate cc ON (cc.block_id = b.block_id)
              JOIN chain_candidate ints ON (
                       ints.chain_id = cc.chain_id
                   AND ints.in_longest = 1
                   AND ints.block_height * ? + ? = cc.block_height)
             WHERE cc.in_longest = 1
               AND cc.chain_id = ?""" + (
                "" if stop is None else """
               AND ints.block_height <= ?""") + """
             ORDER BY cc.block_height""",
                                   (interval, start, chain.id)
                                   if stop is None else
                                   (interval, start, chain.id, stop_ix))
        if fmt == "csv":
            ret = NETHASH_HEADER

        elif fmt in ("json", "jsonp"):
            ret = []

        elif fmt == "svg":
            page['template'] = NETHASH_SVG_TEMPLATE
            page['template_vars']['block_time'] = 600  # XXX BTC-specific
            ret = ""

        else:
            return "ERROR: unknown format: " + fmt

        prev_nTime, prev_chain_work = 0, -1

        for row in rows:
            height, nTime, chain_work, nBits = row
            nTime            = float(nTime)
            nBits            = int(nBits)
            target           = util.calculate_target(nBits)
            difficulty       = util.target_to_difficulty(target)
            work             = util.target_to_work(target)
            chain_work       = abe.store.binout_int(chain_work) - work

            if row is not rows[0] or fmt == "svg":
                height           = int(height)
                interval_work    = chain_work - prev_chain_work
                avg_target       = util.work_to_target(
                    interval_work / float(interval))
                #if avg_target == target - 1:
                #    avg_target = target
                interval_seconds = nTime - prev_nTime
                if interval_seconds <= 0:
                    nethash = 'Infinity'
                else:
                    nethash = "%.0f" % (interval_work / interval_seconds,)

                if fmt == "csv":
                    ret += "%d,%d,%d,%d,%.3f,%d,%.0f,%s\n" % (
                        height, nTime, target, avg_target, difficulty, work,
                        interval_seconds / interval, nethash)

                elif fmt in ("json", "jsonp"):
                    ret.append([
                            height, int(nTime), target, avg_target,
                            difficulty, work, chain_work, nethash])

                elif fmt == "svg":
                    ret += '<abe:nethash t="%d" d="%d"' \
                        ' w="%d"/>\n' % (nTime, work, interval_work)

            prev_nTime, prev_chain_work = nTime, chain_work

        if fmt == "csv":
            return ret

        elif fmt == "json":
            page['content_type'] = 'application/json'
            return json.dumps(ret)

        elif fmt == "jsonp":
            page['content_type'] = 'application/javascript'
            return (jsonp or "jsonp") + "(" + json.dumps(ret) + ")"

        elif fmt == "svg":
            page['content_type'] = 'image/svg+xml'
            return ret

    def q_totalbc(abe, page, chain):
        """shows the amount of currency ever mined."""
        if chain is None:
            return 'Shows the amount of currency ever mined.\n' \
                'This differs from the amount in circulation when' \
                ' coins are destroyed, as happens frequently in Namecoin.\n' \
                'Unlike http://blockexplorer.com/q/totalbc, this does not' \
                ' support future block numbers, and it returns a sum of' \
                ' observed generations rather than a calculated value.\n' \
                '/chain/CHAIN/q/totalbc[/HEIGHT]\n'
        height = path_info_uint(page, None)
        if height is None:
            row = abe.store.selectrow("""
                SELECT b.block_total_satoshis
                  FROM chain c
                  LEFT JOIN block b ON (c.chain_last_block_id = b.block_id)
                 WHERE c.chain_id = ?
            """, (chain.id,))
        else:
            row = abe.store.selectrow("""
                SELECT b.block_total_satoshis
                  FROM chain_candidate cc
                  LEFT JOIN block b ON (b.block_id = cc.block_id)
                 WHERE cc.chain_id = ?
                   AND cc.block_height = ?
                   AND cc.in_longest = 1
            """, (chain.id, height))
            if not row:
                return 'ERROR: block %d not seen yet' % (height,)
        return format_satoshis(row[0], chain) if row else 0

    def q_getreceivedbyaddress(abe, page, chain):
        """shows the amount ever received by a given address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'returns amount of money received by given address (not balance, sends are not subtracted)\n' \
                '/chain/CHAIN/q/getreceivedbyaddress/ADDRESS\n'

        if not util.possible_address(addr):
            return 'ERROR: address invalid'

        version, hash = util.decode_address(addr)
        return format_satoshis(abe.store.get_received(chain.id, hash), chain)

    def q_getsentbyaddress(abe, page, chain):
        """shows the amount ever sent from a given address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'returns amount of money sent from given address\n' \
                '/chain/CHAIN/q/getsentbyaddress/ADDRESS\n'

        if not util.possible_address(addr):
            return 'ERROR: address invalid'

        version, hash = util.decode_address(addr)
        return format_satoshis(abe.store.get_sent(chain.id, hash), chain)

    def q_addressbalance(abe, page, chain):
        """amount ever received minus amount ever sent by a given address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'returns amount of money at the given address\n' \
                '/chain/CHAIN/q/addressbalance/ADDRESS\n'

        if not util.possible_address(addr):
            return 'ERROR: address invalid'

        version, hash = util.decode_address(addr)
        total = abe.store.get_balance(chain.id, hash)

        return ("ERROR: please try again" if total is None else
                format_satoshis(total, chain))

    def q_fb(abe, page, chain):
        """returns an address's firstbits."""

        if not abe.store.use_firstbits:
            raise PageNotFound()

        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return 'Shows ADDRESS\'s firstbits:' \
                ' the shortest initial substring that uniquely and' \
                ' case-insensitively distinguishes ADDRESS from all' \
                ' others first appearing before it or in the same block.\n' \
                'See http://firstbits.com/.\n' \
                'Returns empty if ADDRESS has no firstbits.\n' \
                '/chain/CHAIN/q/fb/ADDRESS\n' \
                '/q/fb/ADDRESS\n'

        if not util.possible_address(addr):
            return 'ERROR: address invalid'

        version, dbhash = util.decode_address(addr)
        ret = abe.store.get_firstbits(
            address_version = version,
            db_pubkey_hash = abe.store.binin(dbhash),
            chain_id = (chain and chain.id))

        if ret is None:
            return 'ERROR: address not in the chain.'

        return ret

    def q_addr(abe, page, chain):
        """returns the full address having the given firstbits."""

        if not abe.store.use_firstbits:
            raise PageNotFound()

        fb = wsgiref.util.shift_path_info(page['env'])
        if fb is None:
            return 'Shows the address identified by FIRSTBITS:' \
                ' the first address in CHAIN to start with FIRSTBITS,' \
                ' where the comparison is case-insensitive.\n' \
                'See http://firstbits.com/.\n' \
                'Returns the argument if none matches.\n' \
                '/chain/CHAIN/q/addr/FIRSTBITS\n' \
                '/q/addr/FIRSTBITS\n'

        return "\n".join(abe.store.firstbits_to_addresses(
                fb, chain_id = (chain and chain.id)))

    def handle_download(abe, page):
        name = abe.args.download_name
        if name is None:
            name = re.sub(r'\W+', '-', ABE_APPNAME.lower()) + '-' + ABE_VERSION
        fileobj = lambda: None
        fileobj.func_dict['write'] = page['start_response'](
            '200 OK',
            [('Content-type', 'application/x-gtar-compressed'),
             ('Content-disposition', 'filename=' + name + '.tar.gz')])
        import tarfile
        with tarfile.TarFile.open(fileobj=fileobj, mode='w|gz',
                                  format=tarfile.PAX_FORMAT) as tar:
            tar.add(os.path.split(__file__)[0], name)
        raise Streamed()

    def serve_static(abe, path, start_response):
        slen = len(abe.static_path)
        if path[:slen] != abe.static_path:
            raise PageNotFound()
        path = path[slen:]
        try:
            # Serve static content.
            # XXX Should check file modification time and handle HTTP
            # if-modified-since.  Or just hope serious users will map
            # our htdocs as static in their web server.
            # XXX is "+ '/' + path" adequate for non-POSIX systems?
            found = open(abe.htdocs + '/' + path, "rb")
            import mimetypes
            type, enc = mimetypes.guess_type(path)
            # XXX Should do something with enc if not None.
            # XXX Should set Content-length.
            start_response('200 OK', [('Content-type', type or 'text/plain')])
            return found
        except IOError:
            raise PageNotFound()

    # Change this if you want empty or multi-byte address versions.
    def is_address_version(abe, v):
        return len(v) == 1

    def short_link(abe, page, link):
        base = abe.base_url
        if base is None:
            env = page['env'].copy()
            env['SCRIPT_NAME'] = posixpath.normpath(
                posixpath.dirname(env['SCRIPT_NAME'] + env['PATH_INFO'])
                + '/' + page['dotdot'])
            env['PATH_INFO'] = link
            full = wsgiref.util.request_uri(env)
        else:
            full = base + link

        return ['<p class="shortlink">Short Link: <a href="',
                page['dotdot'], link, '">', full, '</a></p>\n']

    def fix_path_info(abe, env):
        ret = True
        pi = env['PATH_INFO']
        pi = posixpath.normpath(pi)
        if pi[-1] != '/' and env['PATH_INFO'][-1:] == '/':
            pi += '/'
        if pi == '/':
            pi += abe.home
            if not '/' in abe.home:
                ret = False
        if pi == env['PATH_INFO']:
            ret = False
        else:
            env['PATH_INFO'] = pi
        return ret

def find_htdocs():
    return os.path.join(os.path.split(__file__)[0], 'htdocs')

def get_int_param(page, name):
    vals = page['params'].get(name)
    return vals and int(vals[0])

def path_info_uint(page, default):
    ret = path_info_int(page, None)
    if ret is None or ret < 0:
        return default
    return ret

def path_info_int(page, default):
    s = wsgiref.util.shift_path_info(page['env'])
    if s is None:
        return default
    try:
        return int(s)
    except ValueError:
        return default

def format_time(nTime):
    import time
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(nTime)))

def format_satoshis(satoshis, chain, abe=None):
    decimals = DEFAULT_DECIMALS if chain.decimals is None else chain.decimals
    coin = 10 ** decimals
    if abe is not None:
        coin = abe.get_blockchainparams(chain).get('native-currency-multiple', coin)

    if satoshis is None:
        return ''
    if satoshis < 0:
        return '-' + format_satoshis(-satoshis, chain)
    satoshis = int(satoshis)
    integer = satoshis / coin
    frac = satoshis % coin
    return (str(integer) +
            ('.' + (('0' * decimals) + str(frac))[-decimals:])
            .rstrip('0').rstrip('.'))

def format_difficulty(diff):
    idiff = int(diff)
    ret = '.%03d' % (int(round((diff - idiff) * 1000)),)
    while idiff > 999:
        ret = (' %03d' % (idiff % 1000,)) + ret
        idiff /= 1000
    return str(idiff) + ret

# MULTICHAIN START
def hash_to_address_link(version, hash, dotdot, truncate_to=None, text=None, checksum=None):
# MULTICHAIN END
    if hash == DataStore.NULL_PUBKEY_HASH:
        return 'Destroyed'
    if hash is None:
        return 'UNKNOWN'
# MULTICHAIN START
    if checksum is None:
        addr = util.hash_to_address(version, hash)
    else:
        addr = util.hash_to_address_multichain(version, hash, checksum)
# MULTICHAIN END
    if text is not None:
        visible = text
    elif truncate_to is None:
        visible = addr
    else:
        visible = addr[:truncate_to] + '...'
# MULTICHAIN START
    return ['<a href="', dotdot, 'address/', addr, '">', visible, '</a>']
# MULTICHAIN END
def decode_script(script):
    if script is None:
        return ''
    try:
        return deserialize.decode_script(script)
    except KeyError as e:
        return 'Nonstandard script'

def b58hex(b58):
    try:
        return base58.b58decode(b58, None).encode('hex_codec')
    except Exception:
        raise PageNotFound()

def hexb58(hex):
    return base58.b58encode(hex.decode('hex_codec'))

def block_shortlink(block_hash):
    zeroes = 0
    for c in block_hash:
        if c == '0':
            zeroes += 1
        else:
            break
    zeroes &= ~1
    return hexb58("%02x%s" % (zeroes / 2, block_hash[zeroes : zeroes+12]))

def shortlink_block(link):
    try:
        data = base58.b58decode(link, None)
    except Exception:
        raise PageNotFound()
    return ('00' * ord(data[0])) + data[1:].encode('hex_codec')

def is_hash_prefix(s):
    return HASH_PREFIX_RE.match(s) and len(s) >= HASH_PREFIX_MIN

def flatten(l):
    if isinstance(l, list):
        return ''.join(map(flatten, l))
    if l is None:
        raise Exception('NoneType in HTML conversion')
    if isinstance(l, unicode):
# MULTICHAIN START
        return l.decode('unicode-escape')
    return str(l).decode('unicode-escape')
# MULTICHAIN END

def redirect(page):
    uri = wsgiref.util.request_uri(page['env'])
    page['start_response'](
        '301 Moved Permanently',
        [('Location', str(uri)),
         ('Content-Type', 'text/html')])
    return ('<html><head><title>Moved</title></head>\n'
            '<body><h1>Moved</h1><p>This page has moved to '
            '<a href="' + uri + '">' + uri + '</a></body></html>')

def serve(store):
    args = store.args
    abe = Abe(store, args)

    # Hack preventing wsgiref.simple_server from resolving client addresses
    bhs = __import__('BaseHTTPServer')
    bhs.BaseHTTPRequestHandler.address_string = lambda x: x.client_address[0]
    del(bhs)

    if args.query is not None:
        def start_response(status, headers):
            pass
        import urlparse
        parsed = urlparse.urlparse(args.query)
# MULTICHAIN START
        print(abe({
# MULTICHAIN END
                'SCRIPT_NAME':  '',
                'PATH_INFO':    parsed.path,
                'QUERY_STRING': parsed.query
# MULTICHAIN START
                }, start_response))
# MULTICHAIN END
    elif args.host or args.port:
        # HTTP server.
        if args.host is None:
            args.host = "localhost"
        from wsgiref.simple_server import make_server
# MULTICHAIN START
        from wsgiref import simple_server
        class ExplorerWSGIServer(simple_server.WSGIServer):
            # To increase the backlog
            request_queue_size = 500
        port = int(args.port or 80)
        httpd = make_server(args.host, port, abe, ExplorerWSGIServer)
        abe.log.warning("Listening on http://%s:%d", args.host, port)
        # Launch background loading of transactions
        interval = float( abe.store.catch_up_tx_interval_secs )
        def background_catch_up():
            """
            Background thread to make dummy requests and trigger abe.store.catch_up().
            Thread is set as daemon so CTRL-C interrupt will terminate application and not block on thread/timer.
            """
            while True:
                time.sleep(interval)
                s = 'http://{0}:{1}'.format(args.host, port)
                req = urllib2.Request(s)
                try:
                    response = urllib2.urlopen(req)
                    response.read()
                except Exception as e:
                    pass
        thread = threading.Thread(target=background_catch_up, args=())
        thread.daemon = True
        thread.start()
        abe.log.warning("Launched background thread to catch up tx every {0} seconds".format(interval))
# MULTICHAIN END
        # httpd.shutdown() sometimes hangs, so don't call it.  XXX
        httpd.serve_forever()
    else:
        # FastCGI server.
        from flup.server.fcgi import WSGIServer

        # In the case where the web server starts Abe but can't signal
        # it on server shutdown (because Abe runs as a different user)
        # we arrange the following.  FastCGI script passes its pid as
        # --watch-pid=PID and enters an infinite loop.  We check every
        # minute whether it has terminated and exit when it has.
        wpid = args.watch_pid
        if wpid is not None:
            wpid = int(wpid)
            interval = 60.0  # XXX should be configurable.
            from threading import Timer
            import signal
            def watch():
                if not process_is_alive(wpid):
                    abe.log.warning("process %d terminated, exiting", wpid)
                    #os._exit(0)  # sys.exit merely raises an exception.
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                abe.log.log(0, "process %d found alive", wpid)
                Timer(interval, watch).start()
            Timer(interval, watch).start()
        WSGIServer(abe).run()

def process_is_alive(pid):
    # XXX probably fails spectacularly on Windows.
    import errno
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        if e.errno == errno.EPERM:
            return True  # process exists, but we can't send it signals.
        if e.errno == errno.ESRCH:
            return False # no such process.
        raise

def list_policies():
    import pkgutil
    import Chain
    policies = []
    for _, name, ispkg in pkgutil.iter_modules(path=[os.path.dirname(Chain.__file__)]):
        if not ispkg:
            policies.append(name)
    return policies

def show_policy(policy):
    import inspect
    import Chain
    try:
        chain = Chain.create(policy)
    except ImportError as e:
        print("%s: policy unavailable (%s)" % (policy, e.message))
        return

    print("%s:" % policy)

    parents = []
    for cls in type(chain).__mro__[1:]:
        if cls == Chain.BaseChain:
            break
        parents.append(cls)
    if parents:
        print("  Inherits from:")
        for cls in parents:
            print("    %s" % cls.__name__)

    params = []
    for attr in chain.POLICY_ATTRS:
        val = getattr(chain, attr, None)
        if val is not None:
            params.append((attr, val))
    if params:
        print("  Parameters:")
        for attr, val in params:
            try:
                try:
                    val = json.dumps(val)
                except UnicodeError:
                    if type(val) == bytes:
                        # The value could be a magic number or address version.
                        val = json.dumps(unicode(val, 'latin_1'))
                    else:
                        val = repr(val)
            except TypeError as e:
                val = repr(val)
            print("    %s: %s" % (attr, val))

    doc = inspect.getdoc(chain)
    if doc is not None:
        print("  %s" % doc.replace('\n', '\n  '))

def create_conf():
    conf = {
        "port":                     None,
        "host":                     None,
        "query":                    None,
        "no_serve":                 None,
        "no_load":                  None,
        "timezone":                 None,
        "debug":                    None,
        "static_path":              None,
        "document_root":            None,
        "auto_agpl":                None,
        "download_name":            None,
        "watch_pid":                None,
        "base_url":                 None,
        "logging":                  None,
        "address_history_rows_max": None,
        "shortlink_type":           None,

        "template":     DEFAULT_TEMPLATE,
        "template_vars": {
            "ABE_URL": ABE_URL,
            "APPNAME": ABE_APPNAME,
            "VERSION": ABE_VERSION,
            "COPYRIGHT": COPYRIGHT,
            "COPYRIGHT_YEARS": COPYRIGHT_YEARS,
            "COPYRIGHT_URL": COPYRIGHT_URL,
            "CONTENT_TYPE": DEFAULT_CONTENT_TYPE,
            "HOMEPAGE": DEFAULT_HOMEPAGE,
            },
        }
    conf.update(DataStore.CONFIG_DEFAULTS)
    return conf

def main(argv):
    if argv[0] == '--show-policy':
        for policy in argv[1:] or list_policies():
            show_policy(policy)
        return 0
    elif argv[0] == '--list-policies':
        print("Available chain policies:")
        for name in list_policies():
            print("  %s" % name)
        return 0

    args, argv = readconf.parse_argv(argv, create_conf())

    if not argv:
        pass
    elif argv[0] in ('-h', '--help'):
        print ("""Usage: python -m Abe.abe [-h] [--config=FILE] [--CONFIGVAR=VALUE]...

A Bitcoin block chain browser.

  --help                    Show this help message and exit.
  --version                 Show the program version and exit.
  --print-htdocs-directory  Show the static content directory name and exit.
  --list-policies           Show the available policy names for --datadir.
  --show-policy POLICY...   Describe the given policy.
  --query /q/COMMAND        Show the given URI content and exit.
  --config FILE             Read options from FILE.

All configuration variables may be given as command arguments.
See abe.conf for commented examples.""")
        return 0
    elif argv[0] in ('-v', '--version'):
# MULTICHAIN START
        print(ABE_APPNAME, ABE_VERSION)
        print("Schema version", DataStore.SCHEMA_VERSION)
# MULTICHAIN END
        return 0
    elif argv[0] == '--print-htdocs-directory':
# MULTICHAIN START
        print(find_htdocs())
# MULTICHAIN END
        return 0
    else:
        sys.stderr.write(
            "Error: unknown option `%s'\n"
            "See `python -m Abe.abe --help' for more information.\n"
            % (argv[0],))
        return 1

    logging.basicConfig(
        stream=sys.stdout,
        level = logging.DEBUG if args.query is None else logging.ERROR,
        format=DEFAULT_LOG_FORMAT)
    if args.logging is not None:
        import logging.config as logging_config
        logging_config.dictConfig(args.logging)

    # Set timezone
    if args.timezone:
        os.environ['TZ'] = args.timezone

    if args.auto_agpl:
        import tarfile

    # --rpc-load-mempool loops forever, make sure it's used with
    # --no-load/--no-serve so users know the implications
    if args.rpc_load_mempool and not (args.no_load or args.no_serve):
        sys.stderr.write("Error: --rpc-load-mempool requires --no-serve\n")
        return 1

    store = make_store(args)
    if (not args.no_serve):
        serve(store)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
