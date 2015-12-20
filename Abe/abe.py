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
import optparse
import re
from cgi import escape
import posixpath
import wsgiref.util
import time
import calendar
import math
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
# MULTICHAIN END

__version__ = version.__version__
# MULTICHAIN START
ABE_APPNAME = "MultiChain Explorer"
ABE_VERSION = __version__
ABE_URL = 'https://github.com/multichain/multichain-explorer'

COPYRIGHT_YEARS = '2011-2015'
COPYRIGHT = "Coin Sciences Ltd and Abe developers"
COPYRIGHT_URL = 'https://github.com/multichain/multichain-explorer'
# MULTICHAIN END
DONATIONS_BTC = '1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf'
DONATIONS_NMC = 'NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK'

TIME1970 = time.strptime('1970-01-01','%Y-%m-%d')
EPOCH1970 = calendar.timegm(TIME1970)

# Abe-generated content should all be valid HTML and XHTML fragments.
# Configurable templates may contain either.  HTML seems better supported
# under Internet Explorer.
DEFAULT_CONTENT_TYPE = "text/html; charset=utf-8"
DEFAULT_HOMEPAGE = "chains";
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
</head>
<body>
    <div class="container">
    <h1><a href="%(dotdot)s%(HOMEPAGE)s"><img src="%(dotdot)s%(STATIC_PATH)slogo32.png" alt="MultiChain logo" /></a> %(h1)s
    </h1>
    %(body)s
    <p><a href="%(dotdot)sq">API</a> (machine-readable pages)</p>
    <p style="font-size: smaller">
        <span style="font-style: italic">
            Powered by <a href="%(ABE_URL)s">%(APPNAME)s</a>
        </span>
        %(download)s
    </p>
    </div>
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="%(dotdot)s%(STATIC_PATH)sjs/jquery-1.11.3.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="%(dotdot)s%(STATIC_PATH)sjs/bootstrap.min.js"></script>
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
            }
        if 'QUERY_STRING' in env:
            page['params'] = urlparse.parse_qs(env['QUERY_STRING'])

        if abe.fix_path_info(env):
            abe.log.debug("fixed path_info")
            return redirect(page)

        cmd = wsgiref.util.shift_path_info(env)
        handler = abe.get_handler(cmd)

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
        except NoSuchChainError, e:
            page['body'] += [
                '<p class="error">'
                'Sorry, I don\'t know about that chain!</p>\n']
        except Redirect:
            return redirect(page)
        except Streamed:
            return ''
        except Exception:
            abe.store.rollback()
            raise

        abe.store.rollback()  # Close implicitly opened transaction.

        start_response(page['status'],
                       [('Content-type', page['content_type']),
                        ('Cache-Control', 'max-age=30')])

        tvars['title'] = flatten(page['title'])
        tvars['h1'] = flatten(page.get('h1') or page['title'])
        tvars['body'] = flatten(page['body'])
        if abe.args.auto_agpl:
            tvars['download'] = (
                ' <a href="' + page['dotdot'] + 'download">Source</a>')

        content = page['template'] % tvars
        if isinstance(content, unicode):
            content = content.encode('UTF-8')
        return [content]

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
            '<tr><th>Chain</th><th>Code</th><th>Block</th><th>Time</th>',
            '<th>Assets</th>'
# MULTICHAIN END
            '<th>Started</th><th>Age (days)</th><th>Coins Created</th>',
            '<th>Avg Coin Age</th><th>',
            '% <a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
            'CoinDD</a></th>',
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
            url = abe.store.get_url_by_chain(chain)
            multichain_name = abe.store.get_multichain_name_by_id(chain.id)
            num_assets = 0
            try:
                resp = util.jsonrpc(multichain_name, url, "listassets")
                num_assets = len(resp)
            except util.JsonrpcException as e:
                #msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
                #if e.code != -5:  # -5: transaction not in index.
                num_assets = -1
                pass
            except IOError as e:
                num_assets = -1

# MULTICHAIN END

            body += [
                '<tr><td><a href="chain/', escape(name), '">',
                escape(name), '</a></td><td>', escape(chain.code3), '</td>']

            if row[1] is not None:
                (height, nTime, hash) = (
                    int(row[1]), int(row[2]), abe.store.hashout_hex(row[3]))

                body += [
                    '<td><a href="block/', hash, '">', height, '</a></td>',
                    '<td>', format_time(nTime), '</td>']

# MULTICHAIN START
                body += '<td>'
                if chain.__class__.__name__ is "MultiChain":
                    if num_assets == -1:
                        body += '<span class="label label-danger">No Connection</span>'
                    elif num_assets>=0:
                        body += ['<a href="assets/%d">' % int(chain.id), num_assets, '</a>']
                body += '</td>'
# MULTICHAIN END

                if row[6] is not None and row[7] is not None:
                    (seconds, satoshis, ss, total_ss) = (
                        int(row[4]), int(row[5]), int(row[6]), int(row[7]))

                    started = nTime - seconds
                    chain_age = now - started
                    since_block = now - nTime

                    if satoshis == 0:
                        avg_age = '&nbsp;'
                    else:
                        avg_age = '%5g' % ((float(ss) / satoshis + since_block)
                                           / 86400.0)

                    if chain_age <= 0:
                        percent_destroyed = '&nbsp;'
                    else:
                        more = since_block * satoshis
                        denominator = total_ss + more
                        if denominator <= 0:
                            percent_destroyed = '&nbsp;'
                        else:
                            percent_destroyed = '%5g%%' % (
                                100.0 - (100.0 * (ss + more) / denominator))

                    body += [
                        '<td>', format_time(started)[:10], '</td>',
                        '<td>', '%5g' % (chain_age / 86400.0), '</td>',
                        '<td>', format_satoshis(satoshis, chain), '</td>',
                        '<td>', avg_age, '</td>',
                        '<td>', percent_destroyed, '</td>']

            body += ['</tr>\n']
        body += ['</table>\n']
        if len(rows) == 0:
            body += ['<p>No block data found.</p>\n']

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
        if data['binaddr'] is None:
            return 'Unknown'
        if 'subbinaddr' in data:
            # Multisig or known P2SH.
            ret = [hash_to_address_link(chain.script_addr_vers, data['binaddr'], dotdot, text='Escrow'),
                   ' ', data['required_signatures'], ' of']
            for binaddr in data['subbinaddr']:
                ret += [' ', hash_to_address_link(data['address_version'], binaddr, dotdot, 10)]
            return ret
        return hash_to_address_link(data['address_version'], data['binaddr'], dotdot)

    def call_handler(abe, page, cmd):
        handler = abe.get_handler(cmd)
        if handler is None:
            raise PageNotFound()
        handler(page)

    def handle_chain(abe, page):
        symbol = wsgiref.util.shift_path_info(page['env'])
        chain = abe.chain_lookup_by_name(symbol)
        page['chain'] = chain

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
        for c in (20, 50, 100, 500, 2016):
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
# MULTICHAIN END
                 '<th>Transactions</th><th>Value Out</th>',
                 '<th>Difficulty</th><th>Outstanding</th>',
                 '<th>Average Age</th><th>Chain Age</th>',
                 '<th>% ',
                 '<a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
                 'CoinDD</a></th>',
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

            if satoshis == 0:
                avg_age = '&nbsp;'
            else:
                avg_age = '%5g' % (ss / satoshis / 86400.0)

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
                miner_address = abe.format_addresses(miner_txout, page['dotdot'], chain)
                miner_address = miner_address[0:6]
# MULTICHAIN END

            body += [
                '<tr><td><a href="', page['dotdot'], 'block/',
                abe.store.hashout_hex(hash),
                '">', height, '</a>'
# MULTICHAIN START
                '</td><td>', miner_address,
# MULTICHAIN END
                '</td><td>', format_time(int(nTime)),
                '</td><td>', num_tx,
                '</td><td>', format_satoshis(value_out, chain),
                '</td><td>', util.calculate_difficulty(int(nBits)),
                '</td><td>', format_satoshis(satoshis, chain),
                '</td><td>', avg_age,
                '</td><td>', '%5g' % (seconds / 86400.0),
                '</td><td>', percent_destroyed,
                ['</td><td>', '%8g' % ss,
                 '</td><td>', '%8g' % total_ss] if extra else '',
                '</td></tr>\n']

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
# MULTICHAIN END
            page['h1'] = ['<a href="', page['dotdot'], 'chain/',
                          escape(chain.name), '?hi=', b['height'], '">',
                          escape(chain.name), '</a> ', b['height']]
        else:
            page['title'] = ['Block ', b['hash'][:4], '...', b['hash'][-10:]]

        body += abe.short_link(page, 'b/' + block_shortlink(b['hash']))

        is_stake_chain = chain.has_feature('nvc_proof_of_stake')
        is_stake_block = is_stake_chain and b['is_proof_of_stake']

# MULTICHAIN START
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
        miner_address = abe.format_addresses(miner_txout, page['dotdot'], chain)
        body += html_keyvalue_tablerow('Miner', miner_address)

        body += html_keyvalue_tablerow('Version', b['version'])
        body += html_keyvalue_tablerow('Transaction Merkle Root', b['hashMerkleRoot'])
        body += html_keyvalue_tablerow('Time', b['nTime'] , ' (' , format_time(b['nTime']) , ')')
        body += html_keyvalue_tablerow('Difficulty', format_difficulty(util.calculate_difficulty(b['nBits'])) , ' (Bits: %x)' % (b['nBits'])) 
        body += html_keyvalue_tablerow('Cumulative Difficulty', format_difficulty(util.work_to_difficulty(b['chain_work'])) if b['chain_work'] is not None else '')


        body += html_keyvalue_tablerow('Nonce', b['nNonce'])
        body += html_keyvalue_tablerow('Transactions',len(b['transactions']))
        body += html_keyvalue_tablerow('Value out', format_satoshis(b['value_out'], chain)) 
        body += html_keyvalue_tablerow('Transaction Fees', format_satoshis(b['fees'], chain)) 

        body += html_keyvalue_tablerow('Average Coin Age', '%6g' % (b['satoshi_seconds'] / 86400.0 / b['chain_satoshis']) + ' days' if b['chain_satoshis'] and (b['satoshi_seconds'] is not None) else '')

        body += html_keyvalue_tablerow('Coin-days Destroyed', '' if b['satoshis_destroyed'] is None else format_satoshis(b['satoshis_destroyed'] / 86400.0, chain))

        body += html_keyvalue_tablerow('Cumulative Coin-days Destroyed', '%6g%%' %
             (100 * (1 - float(b['satoshi_seconds']) / b['chain_satoshi_seconds'])) if b['chain_satoshi_seconds'] else '')

        # ['sat=',b['chain_satoshis'],';sec=',seconds,';ss=',b['satoshi_seconds'],
        # ';total_ss=',b['chain_satoshi_seconds'],';destroyed=',b['satoshis_destroyed']]
        # if abe.debug else '',

        body += ['</table>']


        body += ['<h3>Transactions</h3>\n']

        body += ['<table class="table table-striped"><tr><th>Transaction</th><th>Fee</th>'
                 '<th>Size (kB)</th><th>From (amount)</th><th>To (amount)</th>'
                 '</tr>\n']
# MULTICHAIN END

        for tx in b['transactions']:
# MULTICHAIN START
            # Describe MultiChain specific transaction
            label = None
            labeltype = 'success'
            try:
                mytx = abe.store.export_tx(tx_hash = tx['hash'], format = 'browser')
            except DataStore.MalformedHash:
                mytx = None

            if mytx is not None:
                for txout in mytx['out']:
                    if label is not None:
                        # we have found the main purpose of this tx
                        break
                    script_type, data = chain.parse_txout_script(txout['binscript'])
                    if script_type is Chain.SCRIPT_TYPE_MULTICHAIN:
                        data = util.get_multichain_op_drop_data(txout['binscript'])
                        if data is not None:
                            opdrop_type, val = util.parse_op_drop_data(data)
                            if opdrop_type==util.OP_DROP_TYPE_ISSUE_ASSET:
                                label = 'Issue Asset'
                            elif opdrop_type==util.OP_DROP_TYPE_SEND_ASSET:
                                label = 'Send Asset'
                            elif opdrop_type==util.OP_DROP_TYPE_PERMISSION:
                                label = 'Update Permissions'
                            else:
                                label = 'Unrecognized OP_DROP command'
                                labeltype = 'danger'
                        else:
                            label = 'Unrecognized MultiChain command'
                            labeltype = 'danger'

                    elif script_type is Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN:
                        opreturn_type, val = util.parse_op_return_data(data)
                        if opreturn_type==util.OP_RETURN_TYPE_ISSUE_ASSET:
                            label = 'Issue Asset'
                        #else:
                            #Do nothing
                            #label = 'Unrecognized OP_RETURN metadata'

            if label is None:
                labelclass = ''
            else:
                labelclass='class="' + labeltype + '"'
            body += ['<tr ' + labelclass + '><td><a href="../tx/' + tx['hash'] + '">',
                     tx['hash'][:10], '...</a>']

            if label is not None:
                body += ['<div><span class="label label-' + labeltype + '">', label, '</span></div>']
            body += [
# MULTICHAIN END
                     '</td><td>', format_satoshis(tx['fees'], chain),
                     '</td><td>', tx['size'] / 1000.0,
                     '</td><td>']

            if tx is b['transactions'][0]:
                body += [
                    'POS ' if is_stake_block else '',
                    'Generation: ', format_satoshis(b['generated'], chain), ' + ',
                    format_satoshis(b['fees'], chain), ' total fees']
            else:
                for txin in tx['in']:
                    body += [abe.format_addresses(txin, page['dotdot'], chain), ': ',
                             format_satoshis(txin['value'], chain), '<br />']

            body += ['</td><td>']
            for txout in tx['out']:
                if is_stake_block:
                    if tx is b['transactions'][0]:
                        assert txout['value'] == 0
                        assert len(tx['out']) == 1
                        body += [
                            format_satoshis(b['proof_of_stake_generated'], chain),
                            ' included in the following transaction']
                        continue
                    if txout['value'] == 0:
                        continue

                body += [abe.format_addresses(txout, page['dotdot'], chain), ': ',
                         format_satoshis(txout['value'], chain), '<br />']

            body += ['</td></tr>\n']
        body += '</table>\n'

    def handle_block(abe, page):

        z = page['env']['PATH_INFO']
        abe.store.log.debug(">>> HANDLE_BLOCK CALLED WITH PATH_INFO = %s" % z)

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

    def show_tx(abe, page, tx):
        body = page['body']

        def row_to_html(row, this_ch, other_ch, no_link_text):
            body = page['body']
            body += [
                '<tr>\n',
                '<td><a name="', this_ch, row['pos'], '">', row['pos'],
                '</a></td>\n<td>']
            if row['o_hash'] is None:
                body += [no_link_text]
            else:
                body += [
                    '<a href="', row['o_hash'], '#', other_ch, row['o_pos'],
                    '">', row['o_hash'][:10], '...:', row['o_pos'], '</a>']
            body += [
                '</td>\n',
                '<td>', format_satoshis(row['value'], chain), '</td>\n',
                '<td>', abe.format_addresses(row, '../', chain), '</td>\n']
            if row['binscript'] is not None:
# MULTICHAIN START
                body += ['<td>', escape(decode_script(row['binscript'])) ]

                msg = None
                msgtype = 'success'
                script_type, data = chain.parse_txout_script(row['binscript'])
                if script_type is Chain.SCRIPT_TYPE_MULTICHAIN:
                    # NOTE: data returned above is pubkeyhash, due to common use to get address, so we extract data ourselves.
                    data = util.get_multichain_op_drop_data(row['binscript'])
                    if data is not None:
                        opdrop_type, val = util.parse_op_drop_data(data)
                        label = util.get_op_drop_type_description(opdrop_type)
                        if opdrop_type==util.OP_DROP_TYPE_ISSUE_ASSET:
                            msg = "MultiChain: Issue %d units of new asset" % val
                        elif opdrop_type==util.OP_DROP_TYPE_SEND_ASSET:
                            quantity = val['quantity']
                            assetref = val['assetref']
                            link = '<a href="../../assetref/' + str(chain.id) + '/' + assetref + '">' + assetref + '</a>'
                            msg = "MultiChain: Send %d units of asset %s" % (quantity, link)
                        elif opdrop_type==util.OP_DROP_TYPE_PERMISSION:
                            msg = "MultiChain: " + val['type'].capitalize() + " "

                            if val['all'] is True:
                                msg += ' all permissions'
                            else:
                                permissions = []
                                if val['connect']:
                                    permissions += ['Connect']
                                if val['send']:
                                    permissions += ['Send']
                                if val['receive']:
                                    permissions += ['Receive']
                                if val['issue']:
                                    permissions += ['Issue']
                                if val['mine']:
                                    permissions += ['Mine']
                                if val['admin']:
                                    permissions += ['Admin']

                                msg += ' permission to '
                                msg += ', '.join("{}".format(item) for item in permissions)

                            if val['type'] is 'grant' and (val['endblock']!=0 or val['endblock']!=4294967295):
                                msg += ' (block range {} - {})'.format(val['startblock'], val['endblock'])
                            #msg += 'Revok ' if val['type'] is 'revoke
                            #msg += ', '.join("{!s}={!r}".format(k,v) for (k,v) in val.iteritems())
                        else:
                            msg = 'Unrecognized MultiChain command'
                            msgtype = 'danger'

                        # msg += '<p/>'
                        # msg += util.long_hex(data)

                if script_type is Chain.SCRIPT_TYPE_MULTICHAIN_OP_RETURN:
                    opreturn_type, val = util.parse_op_return_data(data)
                    label = util.get_op_return_type_description(opreturn_type)
                    if opreturn_type==util.OP_RETURN_TYPE_ISSUE_ASSET:
                        msg = 'MultiChain: Asset metadata'
                        msg += '<p>'
                        msg += 'Name={!s}, Multiplier={!r}'.format(val['name'],val['multiplier'])
                        fields = val['fields']
                        if len(fields)>0:
                            msg += ', '
                            msg += ', '.join("{}={}".format(k.capitalize(),v) for (k,v) in fields.iteritems())
                            # {!s}={!r} creates single quotes around data
                    elif is_coinbase:
                        msg = 'MultiChain: Miner block signature'
                        msgtype = 'info'
                    else:
                        msg = 'Unrecognized MultiChain metadata'
                        msgtype = 'danger'
                        # msg += '<p/>'
                        # msg += util.long_hex(data)

                # Add MultiChain HTML
                if msg is not None:
                    body += ['<div class="alert alert-'+msgtype+'" role="alert">',
                             msg,
                             '</div>']

                body += [ '</td>\n']
# MULTICHAIN END
            body += ['</tr>\n']

        body += abe.short_link(page, 't/' + hexb58(tx['hash'][:14]))
# MULTICHAIN START
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
                escape(tx_cc['chain'].name), ' ',
                tx_cc['block_height'] if tx_cc['in_longest'] else [blk_hash[:10], '...', blk_hash[-4:]],
                '</a> (', format_time(tx_cc['block_nTime']), ')'
                )
# MULTICHAIN END

        if chain is None:
            abe.log.warning('Assuming default chain for Transaction ' + tx['hash'])
            chain = abe.get_default_chain()
# MULTICHAIN START
        body += html_keyvalue_tablerow('Number of inputs', len(tx['in']),
            ' (<a href="#inputs">Jump to inputs</a>)')
        body += html_keyvalue_tablerow('Total in', format_satoshis(tx['value_in'], chain))
        body += html_keyvalue_tablerow('Number of outputs', len(tx['out']),
            ' (<a href="#outputs">Jump to outputs</a>)')
        body += html_keyvalue_tablerow('Total out', format_satoshis(tx['value_out'], chain)) 
        body += html_keyvalue_tablerow('Size', tx['size'], ' bytes')
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
        body += ['<a name="inputs"><h3>Inputs</h3></a>\n<table class="table table-striped">\n',
# MULTICHAIN END
                 '<tr><th>Index</th><th>Previous output</th><th>Amount</th>',
                 '<th>From address</th>']
        if abe.store.keep_scriptsig:
            body += ['<th>ScriptSig</th>']
        body += ['</tr>\n']
        for txin in tx['in']:
            row_to_html(txin, 'i', 'o',
                        'Generation' if is_coinbase else 'Unknown')
        body += ['</table>\n',
# MULTICHAIN START
                 '<a name="outputs"><h3>Outputs</h3></a>\n<table class="table table-striped">\n',
# MULTICHAIN END
                 '<tr><th>Index</th><th>Redeemed at input</th><th>Amount</th>',
                 '<th>To address</th><th>ScriptPubKey</th></tr>\n']
        for txout in tx['out']:
            row_to_html(txout, 'o', 'i', 'Not yet redeemed')

        body += ['</table>\n']

    def handle_rawtx(abe, page):
        abe.do_raw(page, abe.do_rawtx)

# MULTICHAIN START

    # Experimental handler, so we can show permissions
    def handle_mcaddress(abe, page):
        # Shift chain id
        chain_id = wsgiref.util.shift_path_info(page['env'])
        if chain_id in (None, ''):
            raise PageNotFound()

        chain = abe.store.get_chain_by_id(chain_id)
        if chain is None:
            raise PageNotFound()

        # Shift asset ref
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        #page['content_type'] = 'text/html'
        page['title'] = "Address " + address
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # If the HTML link for this handler gets only created for MultiChain networks, we don't need to check class.
        #if chain.__class__.__name__ is "MultiChain":
        try:
            resp = util.jsonrpc(multichain_name, url, "listpermissions", "all", address)
            s = json.dumps(resp, sort_keys=True, indent=2)
            body += ['<h3>Permissions</h3><pre>', s, '</pre>']
        except util.JsonrpcException as e:
            msg= "Failed to get permissions for address: JSON-RPC error({0}): {1}".format(e.code, e.message)
            body += ['<div class="alert alert-danger" role="warning">', msg ,'</div>']
            #return s
        except IOError as e:
            msg= "Failed to get permissions for address: I/O error({0}): {1}".format(e.errno, e.strerror)
            body += ['<div class="alert alert-danger" role="alert">', msg, '</div>']
            #page['title'] = 'IO ERROR'
            #return s

    # Given an asset reference, display info about asset.
    def handle_assetref(abe, page):
        # Shift chain id
        chain_id = wsgiref.util.shift_path_info(page['env'])
        if chain_id in (None, ''):
            raise PageNotFound()

        chain = abe.store.get_chain_by_id(chain_id)
        if chain is None:
            raise PageNotFound()

        # Shift asset ref
        assetref = wsgiref.util.shift_path_info(page['env'])
        if assetref in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        #page['content_type'] = 'text/html'
        page['title'] = chain.name
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)

        # get block height from assetref
        m = re.search('^(\d+)-\d+-\d+$', assetref)
        height = int(m.group(1))

        # ...so no need to export block
        # try:
        #     b = abe.store.export_block(chain, block_number=height)
        # except DataStore.MalformedHash:
        #     body += ['<p class="error">Not in correct format.</p>']
        #     return
        # if b is None:
        #     body += ['<p class="error">Block not found.</p>']
        #     return

        # get asset information and issue tx as json
        try:
            resp = util.jsonrpc(multichain_name, url, "listassets", assetref)
            asset = resp[0]
            issuetxid = asset['issuetxid']
            resp = util.jsonrpc(multichain_name, url, "getrawtransaction", issuetxid, 1)
            issuetx = resp
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            #if e.code != -5:  # -5: transaction not in index.
            # JSON-RPC error(-8): Asset with this reference not found: 5-264-60087
            body += [ msg ]
            return
        except IOError as e:
            msg = "Network connection error"
            body += [ msg ]
            return

        blocktime = issuetx['blocktime']
        blockhash = issuetx['blockhash']
        raw_units = issuetx['vout'][0]['assets'][0]['raw']
        display_qty = issuetx['vout'][0]['assets'][0]['qty']
        name = issuetx['vout'][0]['assets'][0]['name']
        address_to = issuetx['vout'][0]['scriptPubKey']['addresses'][0]
        address_from = issuetx['vout'][2]['scriptPubKey']['addresses'][0]
        native_amount = issuetx['vout'][0]['value']

        body += ['<h3>Asset Summary "' + name.capitalize() + '"</h3>\n']
        body += ['<table class="table table-bordered table-condensed">']

        body += html_keyvalue_tablerow('Issue Block Height', '<a href="../../block/', blockhash, '">', height, '</a>')
#                                                                                                                '' b['height'] if b['height'] is not None else '')
        body += html_keyvalue_tablerow('Issue Block Time', blocktime , ' (' , format_time(blocktime) , ')')
        body += html_keyvalue_tablerow('Issue TXID', '<a href="../../tx/' + issuetxid + '">', issuetxid, '</a>')
        body += html_keyvalue_tablerow('Asset Reference', '<a href="../../assetref/' + chain_id + '/' + assetref + '">' + assetref + '</a>')
        body += html_keyvalue_tablerow('Name', '<a href="../../assetref/' + chain_id + '/' + assetref + '">' + name + '</a>')
        body += html_keyvalue_tablerow('Raw units issued', raw_units)
        body += html_keyvalue_tablerow('Display quantity', display_qty)
        body += html_keyvalue_tablerow('Native amount sent', format_satoshis(native_amount, chain))
        body += html_keyvalue_tablerow('Issuer Address', '<a href="../../mcaddress/' + chain_id + '/' + address_from + '">', address_from, '</a>')
        body += html_keyvalue_tablerow('Recipient Address ', '<a href="../../mcaddress/' + chain_id + '/' + address_to + '">', address_to, '</a>')
        body += ['</table>']

        #body += ['<h3>', asset['name'], '(Asset Reference ', assetref, ')', '</h3>']
        body += ['<p class="text-right">']
        body += ['<button href="#RawJson" class="btn btn-default btn-xs" data-toggle="collapse">MultiChain JSON</button>']
        body += ['<div id="RawJson" class="collapse"><pre>', json.dumps(resp, sort_keys=True, indent=2), '</pre></div></p>']
        #body += [' <a role="button" class="btn btn-default btn-xs" href="../rawtx/', tx['hash'], '">Bitcoin JSON</a>']

    # Page to show the assets that exist on a chain
    def handle_assets(abe, page):
        chain_id = wsgiref.util.shift_path_info(page['env'])
        if chain_id in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()
        chain = abe.store.get_chain_by_id(chain_id)
        if chain is None:
            raise PageNotFound()

        page['content_type'] = 'text/html'
        page['title'] = chain.name
        body = page['body']

        url = abe.store.get_url_by_chain(chain)
        multichain_name = abe.store.get_multichain_name_by_id(chain.id)
        num_assets = 0
        try:
            resp = util.jsonrpc(multichain_name, url, "listassets")
            num_assets = len(resp)
        except util.JsonrpcException as e:
            msg= "JSON-RPC error({0}): {1}".format(e.code, e.message)
            #if e.code != -5:  # -5: transaction not in index.
            body += [ msg ]
            return
        except IOError as e:
            msg = "Network connection error"
            body += [ msg ]
            return

        if num_assets is 0:
            body += [ "No assets issued"]
            return

        body += ['<h3>Assets</h3>']

        body += ['<table class="table table-striped"><tr><th>Asset Name</th><th>Asset Reference</th>'
                 '<th>Genesis Transaction</th><th>Multiple</th><th>Units</th><th>Details</th>'
                 '<th>Display Quantity</th><th>Issue Raw Quantity</th>'
                 '</tr>']

        for asset in resp:
# MULTICHAIN START
            details = ', '.join("{}={}".format(k,v) for (k,v) in asset['details'].iteritems())
# MULTICHAIN END
            issueqty = str(asset['issueqty'])
            issueraw = str(asset['issueraw'])
            body += ['<tr><td><a href="../../assetref/' + chain_id + '/' + asset['assetref'] + '">' + asset['name'] + '</a>',
                     '</td><td><a href="../../assetref/' + chain_id + '/' + asset['assetref'] + '">' + asset['assetref'] + '</a>',
                     '</td><td><a href="../../tx/' + asset['issuetxid'] + '">',
                     asset['issuetxid'][:20], '...</a>',
                     '</td><td>', asset['multiple'],
                     '</td><td>', asset['units'],
                     '</td><td>', details,
                     '</td><td>', issueqty,
                     '</td><td>', issueraw,
                     '</td></tr>']

        body += ['</table>']

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
                #is_coinbase = (tx_cc['tx_pos'] == 0)
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

    def handle_address(abe, page):
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
            body += ['<p>Address not seen on the network.</p>']
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
                    other = util.hash_to_address(vers, binaddr)
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
        body += abe.short_link(page, 'a/' + link)
# MULTICHAIN START
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
                value = hash_to_address_link(chain.script_addr_vers, elt['binaddr'], page['dotdot'], text=value)

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
            ' public key hash, or chain name:</label></p>'
            '<form class="form-inline" action="', page['dotdot'], 'search"><p>\n'
            '<div class="form-group">'
            '<input id="search1" type="text" name="q" size="64" value="', escape(q), '" />'
            '<button type="submit" class="btn btn-default">Search</button>\n'
            '<p class="help-block">Address or hash search requires at least the first ',
            HASH_PREFIX_MIN, ' characters.</p></div></form>\n']
# MULTICHAIN END

    def handle_search(abe, page):
        page['title'] = 'Search'
        q = (page['params'].get('q') or [''])[0]
        if q == '':
            page['body'] = [
                '<p>Please enter search terms.</p>\n', abe.search_form(page)]
            return

        found = []
        if HEIGHT_RE.match(q):      found += abe.search_number(int(q))
        if util.possible_address(q):found += abe.search_address(q)
        elif ADDR_PREFIX_RE.match(q):found += abe.search_address_prefix(q)
        if is_hash_prefix(q):       found += abe.search_hash_prefix(q)
        found += abe.search_general(q)
        abe.show_search_results(page, found)

    def show_search_results(abe, page, found):
        if not found:
            page['body'] = [
                '<p>No results found.</p>\n', abe.search_form(page)]
            return

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
        return { 'name': 'Address ' + address, 'uri': 'address/' + address }

    def search_address(abe, address):
        try:
            binaddr = base58.bc_address_to_hash_160(address)
        except Exception:
            return abe.search_address_prefix(address)
        return [abe._found_address(address)]

    def search_address_prefix(abe, ap):
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
            addrs = addrs.split("|");
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

        if max_rows >= 0 and len(received_rows) > max_rows:
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
        version, hash = util.decode_check_address(addr)
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
            page['template_vars']['block_time'] = 600;  # XXX BTC-specific
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

def format_satoshis(satoshis, chain):
    decimals = DEFAULT_DECIMALS if chain.decimals is None else chain.decimals
    coin = 10 ** decimals

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
        idiff = idiff / 1000
    return str(idiff) + ret

def hash_to_address_link(version, hash, dotdot, truncate_to=None, text=None):
    if hash == DataStore.NULL_PUBKEY_HASH:
        return 'Destroyed'
    if hash is None:
        return 'UNKNOWN'
    addr = util.hash_to_address(version, hash)

    if text is not None:
        visible = text
    elif truncate_to is None:
        visible = addr
    else:
        visible = addr[:truncate_to] + '...'

    return ['<a href="', dotdot, 'address/', addr, '">', visible, '</a>']

def decode_script(script):
    if script is None:
        return ''
    try:
        return deserialize.decode_script(script)
    except KeyError, e:
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
        return l
    return str(l)

def redirect(page):
    uri = wsgiref.util.request_uri(page['env'])
    page['start_response'](
        '301 Moved Permanently',
        [('Location', uri),
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
        print abe({
                'SCRIPT_NAME':  '',
                'PATH_INFO':    parsed.path,
                'QUERY_STRING': parsed.query
                }, start_response)
    elif args.host or args.port:
        # HTTP server.
        if args.host is None:
            args.host = "localhost"
        from wsgiref.simple_server import make_server
        port = int(args.port or 80)
        httpd = make_server(args.host, port, abe)
        abe.log.warning("Listening on http://%s:%d", args.host, port)
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
    except OSError, e:
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
            "DONATIONS_BTC": DONATIONS_BTC,
            "DONATIONS_NMC": DONATIONS_NMC,
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
        print ABE_APPNAME, ABE_VERSION
        print "Schema version", DataStore.SCHEMA_VERSION
        return 0
    elif argv[0] == '--print-htdocs-directory':
        print find_htdocs()
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
