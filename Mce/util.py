# Copyright(C) 2011,2012,2013,2014 by Abe developers.
# Copyright (c) 2010 Gavin Andresen

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

#
# Misc util routines
#

import re
import base58
import Crypto.Hash.SHA256 as SHA256
# MULTICHAIN START
import struct
import deserialize
import Chain
# MULTICHAIN END

try:
    import Crypto.Hash.RIPEMD160 as RIPEMD160
except Exception:
    import ripemd_via_hashlib as RIPEMD160

# This function comes from bitcointools, bct-LICENSE.txt.
def determine_db_dir():
    import os
    import os.path
    import platform
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    elif platform.system() == "Windows":
        return os.path.join(os.environ['APPDATA'], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")

# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]

NULL_HASH = "\0" * 32
GENESIS_HASH_PREV = NULL_HASH

def sha256(s):
    return SHA256.new(s).digest()

def double_sha256(s):
    return sha256(sha256(s))

def sha3_256(s):
    import hashlib
    import sys
    if sys.version_info < (3, 4):
        import sha3
    return hashlib.sha3_256(s).digest()

def pubkey_to_hash(pubkey):
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()

def calculate_target(nBits):
    # cf. CBigNum::SetCompact in bignum.h
    shift = 8 * (((nBits >> 24) & 0xff) - 3)
    bits = nBits & 0x7fffff
    sign = -1 if (nBits & 0x800000) else 1
    return sign * (bits << shift if shift >= 0 else bits >> -shift)

def target_to_difficulty(target):
    return ((1 << 224) - 1) * 1000 / (target + 1) / 1000.0

def calculate_difficulty(nBits):
    return target_to_difficulty(calculate_target(nBits))

def work_to_difficulty(work):
    return work * ((1 << 224) - 1) * 1000 / (1 << 256) / 1000.0

def target_to_work(target):
    # XXX will this round using the same rules as C++ Bitcoin?
    return int((1 << 256) / (target + 1))

def calculate_work(prev_work, nBits):
    if prev_work is None:
        return None
    return prev_work + target_to_work(calculate_target(nBits))

def work_to_target(work):
    return int((1 << 256) / work) - 1

def get_search_height(n):
    if n < 2:
        return None
    if n & 1:
        return n >> 1 if n & 2 else n - (n >> 2)
    bit = 2
    while (n & bit) == 0:
        bit <<= 1
    return n - bit

ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{26,}\\Z')

def possible_address(string):
    return ADDRESS_RE.match(string)

def hash_to_address(version, hash):
    vh = version + hash
    return base58.b58encode(vh + double_sha256(vh)[:4])

# MULTICHAIN START
def hash_to_address_multichain(version, hash, checksum):
    """
    Format address the MultiChain way, with version bytes and checksum bytes.
    http://www.multichain.com/developers/address-format/

    :param version:
    :param hash:
    :param checksum:
    :return:
    """
    n = len(version)
    pos = 0
    i =0
    vh = ''
    while i<n:
        vh += version[i:i+1]
        vh += hash[pos:pos+5]
        i += 1
        pos += 5
    vh += hash[pos:]

    dh = double_sha256(vh)
    a = dh[:4]
    b = checksum
    new_checksum = ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])
    vh += new_checksum[:4]
    return base58.b58encode(vh)

def decode_check_address_multichain(address):
    version, hash = decode_address_multichain(address)
    if version is not None and hash is not None:
        raw = base58.b58decode(address, None)
        checksum = raw[-4:0]
        if hash_to_address_multichain(version, hash, checksum):
            return version, hash
    return None, None

def decode_address_multichain(address):
    if possible_address(address):
        raw = base58.b58decode(address, None)
        # if len(raw) < 25:
        #     raw = ('\0' * (25 - len(raw))) + raw

        #print "base58 decoded len = {}".format(len(raw))
        raw = raw[:-4] # drop checksum
        #print "no checksum        = {} ".format(len(raw))
        n = len(raw)
        skip = n - 20
        #print "skip num raw     = {} ".format(skip)
        i =0
        resulthash = '' #bytearray()
        resultversion = ''
        while i<n:
            if skip>0 and i % 6 == 0:
                skip = skip - 1
                resultversion += raw[i]
            else:
                resulthash += raw[i]
            i = i + 1
        #print "ripemd length = {}, hex = {}".format(len(resulthash), long_hex(resulthash))
        return resultversion, resulthash
    return None, None
# MULTICHAIN END

def decode_check_address(address):
    if possible_address(address):
        version, hash = decode_address(address)
        if hash_to_address(version, hash) == address:
            return version, hash
    return None, None

def decode_address(addr):
    bytes = base58.b58decode(addr, None)
    if len(bytes) < 25:
        bytes = ('\0' * (25 - len(bytes))) + bytes
    return bytes[:-24], bytes[-24:-4]

class JsonrpcException(Exception):
    def __init__(ex, error, method, params):
        Exception.__init__(ex)
        ex.code = error['code']
        ex.message = error['message']
        ex.data = error.get('data')
        ex.method = method
        ex.params = params
    def __str__(ex):
        return ex.method + ": " + ex.message + " (code " + str(ex.code) + ")"

class JsonrpcMethodNotFound(JsonrpcException):
    pass

# MULTICHAIN START
# MultiChain requires chain_name argument in JSON requests.

def jsonrpc_id_counter():
    if not hasattr(jsonrpc_id_counter, "counter"):
        jsonrpc_id_counter.counter = 0  # it doesn't exist yet, so initialize it
    jsonrpc_id_counter.counter += 1
    return jsonrpc_id_counter.counter

def jsonrpc(chain_name, url, method, *params):
    import json, urllib
    postdata = json.dumps({"jsonrpc": "2.0",
                           "chain_name": chain_name,
# MULTICHAIN END
                           "method": method, "params": params, "id": str(jsonrpc_id_counter())})
    respdata = urllib.urlopen(url, postdata).read()
    resp = json.loads(respdata)

# MULTICHAIN START
#     print("PARAMS: ", params)
#     print("URL:  ", url)
#     print("POST: ", postdata)
#     print("RESP: ", resp)
# MULTICHAIN END

    if resp.get('error') is not None:
        if resp['error']['code'] == -32601:
            raise JsonrpcMethodNotFound(resp['error'], method, params)
        raise JsonrpcException(resp['error'], method, params)
    return resp['result']

def str_to_ds(s):
    import BCDataStream
    ds = BCDataStream.BCDataStream()
    ds.write(s)
    return ds

class CmdLine(object):
    def __init__(self, argv, conf=None):
        self.argv = argv
        if conf is None:
            self.conf = {}
        else:
            self.conf = conf.copy()

    def usage(self):
        return "Sorry, no help is available."

    def init(self):
        import DataStore, readconf, logging, sys
        self.conf.update({ "debug": None, "logging": None })
        self.conf.update(DataStore.CONFIG_DEFAULTS)

        args, argv = readconf.parse_argv(self.argv, self.conf, strict=False)
        if argv and argv[0] in ('-h', '--help'):
# MULTICHAIN START
            print(self.usage())
# MULTICHAIN END
            return None, []

        logging.basicConfig(
            stream=sys.stdout, level=logging.DEBUG, format="%(message)s")
        if args.logging is not None:
            import logging.config as logging_config
            logging_config.dictConfig(args.logging)

        store = DataStore.new(args)

        return store, argv

# Abstract hex-binary conversions for eventual porting to Python 3.
def hex2b(s):
    return s.decode('hex')
def b2hex(b):
    return b.encode('hex')

# MULTICHAIN START
OP_DROP_TYPE_UNKNOWN = 0
OP_DROP_TYPE_ISSUE_ASSET = 1
OP_DROP_TYPE_SEND_ASSET = 2
OP_DROP_TYPE_PERMISSION = 3
OP_DROP_TYPE_ISSUE_MORE_ASSET = 4

OP_RETURN_TYPE_UNKNOWN = 0
OP_RETURN_TYPE_ISSUE_ASSET = 1
OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE = 2
OP_RETURN_TYPE_ISSUE_MORE_ASSET =3

def get_op_drop_type_description(t):
    if t == OP_DROP_TYPE_ISSUE_ASSET:
        return "Issue Asset"
    elif t == OP_DROP_TYPE_SEND_ASSET:
        # A user may not have sent an asset, could be part of change txout.
        return "Asset"
    elif t == OP_DROP_TYPE_PERMISSION:
        return "Permission"
    elif t == OP_DROP_TYPE_ISSUE_MORE_ASSET:
        return "Issue Asset (More)"

    return "Unrecognized Command"

def get_op_return_type_description(t):
    if t == OP_RETURN_TYPE_ISSUE_ASSET:
        return "Issue Asset"
    elif t == OP_RETURN_TYPE_ISSUE_MORE_ASSET:
        return "Issue Asset (More)"
    elif t == OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE:
        return "Miner Signature"
    return "Unrecognized Metadata"


# https://docs.python.org/2/library/struct.html
def parse_op_drop_data(data):
    """
    Return TYPE, DATA where the format of DATA depends on TYPE.

    * OP_DROP_TYPE_ISSUE_ASSET - DATA is the quantity of raw units issued
    * OP_DROP_TYPE_SEND_ASSET  - DATA is a list of dictionary of key values: asset reference, quantity
    * OP_DROP_TYPE_PERMISSION  -  DATA is a dictionary of key values: Permission flags, type (grant/revoke), block range, time

    :param data:
    :return:
    """
    # print "parse_op_drop_data: = %s" % binascii.hexlify(data)
    rettype = OP_DROP_TYPE_UNKNOWN
    retval = None
    if data[0:4]==bytearray.fromhex(u'73706b67'):
        (qty,) = struct.unpack("<Q",data[4:12]);
        rettype = OP_DROP_TYPE_ISSUE_ASSET
        retval = qty
    elif data[0:4]==bytearray.fromhex(u'73706b71') or data[0:4]==bytearray.fromhex(u'73706b6f'):
        # prefix: if txid begins ce8a..., 0x8ace = 35534 is the correct prefix.
        assets = []
        pos = 4
        datalen=len(data)
        while (pos+18)<=datalen:
            (block,offset,prefix,quantity) = struct.unpack("<LLHQ", data[pos:pos+18])
            assetref = "%d-%d-%d" % (block,offset,prefix)
            #print "ASSET SENT %d-%d-%d QTY %d" % (block,offset,prefix,quantity)
            assets.append( {'assetref':assetref, 'quantity':quantity} )
            pos += 18
        if data[0:4]==bytearray.fromhex(u'73706b6f'):
            rettype = OP_DROP_TYPE_ISSUE_MORE_ASSET
        else:
            rettype = OP_DROP_TYPE_SEND_ASSET
        retval = assets
    elif data[0:4]==bytearray.fromhex(u'73706b70'):
        # 4 byte bitmap uint32, uint32 from, unit32 to, uint32 timestamp
        # bitmap connect=1, send=2, receive=4, issue=16, mine=256, admin=4096.
        (bitmap, block_from, block_to, timestamp) = struct.unpack("<LLLL", data[4:])
        revoke = True if block_from==0 and block_to==0 else False
        # print "op_drop payload is ", long_hex(data[4:])
        # print "bitmap %s, %d-%d, time %d" % (str(bin(bitmap))[2:], block_from, block_to, timestamp)
        # literal d = {'x':obj}
        connect = (bitmap & 1) > 0
        send = (bitmap & 2) > 0
        receive = (bitmap & 4) > 0
        issue = (bitmap & 16) > 0
        mine = (bitmap & 256) > 0
        admin = (bitmap & 4096) > 0
        activate = (bitmap & 8192) > 0
        #allsum = 1+2+4+16+256+4096+8192
        #all = (bitmap & allsum) == allsum
        rettype = OP_DROP_TYPE_PERMISSION
        retval = {'connect':connect, 'send':send, 'receive':receive, 'issue':issue, 'mine':mine, 'admin':admin, 'activate':activate,
                  #'all':all,
                  'type':'revoke' if revoke is True else 'grant',
                  'startblock':block_from, 'endblock':block_to}
    return rettype, retval

def parse_op_return_data(data):
    """
    Return TYPE, DATA where the format of DATA depends on TYPE.

    * OP_RETURN_TYPE_ISSUE_ASSET  - DATA is a dictionary of key values: multiplier, name

    :param data:
    :return:
    """
    rettype = OP_RETURN_TYPE_UNKNOWN
    retval = None
    if data[0:4]==bytearray.fromhex(u'53504b61'):
        (multiplier,) = struct.unpack("<L", data[4:8])
        pos = 8
        searchdata = data[pos:]
        assetname= searchdata[:searchdata.index("\0")]
        pos = pos + len(assetname) + 1

        # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
        fields = dict()
        while pos<len(data):
            searchdata = data[pos:]

            # Is this a special property with meaning only for MultiChain?
            if data[pos:pos+1] == "\0":
                assetproplen = ord(data[pos+2:pos+3])
                assetprop = data[pos+3:pos+3+assetproplen]
                if data[pos+1] == "\x02":
                    # Asset property
                    fields['open'] = str(bool(ord(data[pos+3:pos+4])))
                else:
                    # Unknown property
                    fname = "Property at offset {0}".format(pos)
                    fields[fname] = long_hex(assetprop)
                pos = pos + 3 + assetproplen
                continue

            fname = searchdata[:searchdata.index("\0")]
            # print "field name: ", fname, " field name len: ", len(fname)
            pos = pos + len(fname) + 1
            # print "pos of vle: ", pos
            #subdata = subdata[len(fname):]

            flen = ord(data[pos:pos+1])
            pos += 1
            # print "pos of payload: ", pos
            if flen == 253:
                (size,) = struct.unpack('<H', data[pos:pos+2])
                flen = size
                pos += 2
            elif flen == 254:
                (size,) = struct.unpack('<I', data[pos:pos+4])
                flen = size
                pos += 4
            elif flen == 255:
                (size,) = struct.unpack('<Q', data[pos:pos+8])
                flen = size
                pos += 8
            # print "pos of payload: ", pos
            # print "payload length: ", flen
            fields[fname]=data[pos:pos+flen]
            pos += flen

        rettype = OP_RETURN_TYPE_ISSUE_ASSET
        retval = {'multiplier':multiplier, 'name':str(assetname), 'fields':fields}
    elif data[0:4]==bytearray.fromhex(u'53504b62'):
        rettype = OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE
        retval = data[4:]
    elif data[0:4]==bytearray.fromhex(u'53504b63'):
        pos = 4
        searchdata = data[pos:]
        # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
        fields = dict()
        while pos<len(data):
            # Is this a special property with meaning only for MultiChain?
            if data[pos:pos+1] == "\0":
                assetproplen = ord(data[pos+2:pos+3])
                assetprop = data[pos+3:pos+3+assetproplen]
                fname = "Property at offset {0}".format(pos)
                fields[fname] = long_hex(assetprop)
                pos = pos + 3 + assetproplen
                continue

            searchdata = data[pos:]
            fname = searchdata[:searchdata.index("\0")]
            # print "field name: ", fname, " field name len: ", len(fname)
            pos = pos + len(fname) + 1
            # print "pos of vle: ", pos
            #subdata = subdata[len(fname):]

            flen = ord(data[pos:pos+1])
            pos += 1
            # print "pos of payload: ", pos
            if flen == 253:
                (size,) = struct.unpack('<H', data[pos:pos+2])
                flen = size
                pos += 2
            elif flen == 254:
                (size,) = struct.unpack('<I', data[pos:pos+4])
                flen = size
                pos += 4
            elif flen == 255:
                (size,) = struct.unpack('<Q', data[pos:pos+8])
                flen = size
                pos += 8
            # print "pos of payload: ", pos
            # print "payload length: ", flen
            fields[fname]=data[pos:pos+flen]
            pos += flen
        rettype = OP_RETURN_TYPE_ISSUE_MORE_ASSET
        retval = {'multiplier':None, 'name':None, 'fields':fields}

    return rettype, retval

def get_multichain_op_drop_data(script):
    """
    Get OP DROP data.
    :param script: script byte data
    :return:
    """
    try:
        decoded = [x for x in deserialize.script_GetOp(script)]
    except Exception:
        return None
    data = None
    if deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_TEMPLATE):
        data = decoded[5][1]
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_P2SH_TEMPLATE):
        data = decoded[3][1] # 4th element contains the OP_DROP data.
    return data

def format_display_quantity(asset, rawqty):
    """
    Return string containing display quantity of a raw amount formatted based on asset multiple
    :param asset:
    :param rawunits:
    :return:
    """
    multiple = asset['multiple']
    # Float division / rounding problems
    #s = "{:.20f}".format(1.0/multiple) #str(1.0/multiple)
    #p = s[::-1].find('.')

    # assume base 10 to keep things simple
    p = len(str(multiple)) - 1

    if p is 0:
        fmt = "{0:d}"
        v = int(rawqty)
    else:
        fmt = "{0:." + "{0}".format(p) + "f}"
        v = float(rawqty) / float(multiple)
    return fmt.format( v )


# MULTICHAIN END
