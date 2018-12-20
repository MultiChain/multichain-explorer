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
import json
import re
import string
# MULTICHAIN START
import struct
import sys
from cgi import escape

import Crypto.Hash.SHA256 as SHA256
import ubjson

import Chain
import base58
import deserialize

# MULTICHAIN END

try:
    import Crypto.Hash.RIPEMD160 as RIPEMD160
except Exception:
    import ripemd_via_hashlib as RIPEMD160


# This function comes from bitcointools, bct-LICENSE.txt.
def determine_db_dir():
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
    return t[0:4] + "..." + t[-4:]


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
        pass
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
    # if not isinstance(version, str):
    #     raise TypeError("version is a " + type(version).__name__)
    # if not isinstance(hash, str):
    #     raise TypeError("hash is a " + type(hash).__name__)
    n = len(version)
    pos = 0
    i = 0
    vh = ''
    while i < n:
        vh += version[i:i + 1]
        vh += hash[pos:pos + 5]
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

        # print "base58 decoded len = {}".format(len(raw))
        raw = raw[:-4]  # drop checksum
        # print "no checksum        = {} ".format(len(raw))
        n = len(raw)
        skip = n - 20
        # print "skip num raw     = {} ".format(skip)
        i = 0
        resulthash = ''  # bytearray()
        resultversion = ''
        while i < n:
            if skip > 0 and i % 6 == 0:
                skip = skip - 1
                resultversion += raw[i]
            else:
                resulthash += raw[i]
            i = i + 1
        # print "ripemd length = {}, hex = {}".format(len(resulthash), long_hex(resulthash))
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
        self.conf.update({"debug": None, "logging": None})
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
OP_DROP_TYPE_CREATE_STREAM = 5
OP_DROP_TYPE_STREAM_ITEM = 6
# OP_DROP_TYPE_STREAM_PERMISSION = 7

OP_DROP_TYPE_SPKN_NEW_ISSUE = 8
OP_DROP_TYPE_FOLLOW_ON_ISSUANCE_METADATA = 9
OP_DROP_TYPE_SPKN_CREATE_STREAM = 10
OP_DROP_TYPE_SPKE = 11
OP_DROP_TYPE_SPKI = 12  # input cache
OP_DROP_TYPE_SPKF = 13
OP_DROP_TYPE_SPKN_CREATE_UPGRADE = 14
OP_DROP_TYPE_SPKN_APPROVE_UPGRADE = 15
OP_DROP_TYPE_RAW_DATA = 16  # spkd
OP_DROP_TYPE_SPKN_CREATE_FILTER = 17

OP_RETURN_TYPE_UNKNOWN = 0
OP_RETURN_TYPE_ISSUE_ASSET = 1
OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE = 2
OP_RETURN_TYPE_SPKC = 3


# OP_RETURN_TYPE_SPKC is used when (1) issuing follow-on units of an asset, (2) when creating a stream

def get_op_drop_type_description(t):
    if t == OP_DROP_TYPE_ISSUE_ASSET:
        return "Issue Asset"
    elif t == OP_DROP_TYPE_SEND_ASSET:
        # A user may not have sent an asset, could be part of change txout.
        return "Asset"
    elif t == OP_DROP_TYPE_PERMISSION:
        return "Approval or Permission"
    elif t == OP_DROP_TYPE_ISSUE_MORE_ASSET:
        return "Issue Asset (Follow On)"
    elif t == OP_DROP_TYPE_CREATE_STREAM:
        return "Create Stream"
    elif t == OP_DROP_TYPE_STREAM_ITEM:
        return "Stream Item"
    # elif t == OP_DROP_TYPE_STREAM_PERMISSION:
    #     return "Stream Permission"
    elif t == OP_DROP_TYPE_SPKI:
        return "Input Cache"
    elif t == OP_DROP_TYPE_SPKN_CREATE_STREAM:
        return "Create Stream"
    elif t == OP_DROP_TYPE_SPKN_CREATE_FILTER:
        return "Create Filter"
    elif t == OP_DROP_TYPE_SPKN_CREATE_UPGRADE:
        return "Create Upgrade"
    elif t == OP_DROP_TYPE_SPKN_APPROVE_UPGRADE:
        return "Approve Upgrade"
    elif t == OP_DROP_TYPE_SPKN_NEW_ISSUE:
        return "Issue Asset (Metadata)"
    elif t == OP_DROP_TYPE_FOLLOW_ON_ISSUANCE_METADATA:
        return "Follow-On Issuance Of Asset (Metadata)"

    elif t == OP_DROP_TYPE_SPKE:
        return "Metadata"

    return "Unrecognized Command"


def get_op_return_type_description(t):
    if t == OP_RETURN_TYPE_ISSUE_ASSET:
        return "Issue Asset"
    elif t == OP_RETURN_TYPE_SPKC:
        return "Issue Asset (Follow On)"
    elif t == OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE:
        return "Miner Signature"
    # TODO: 10007
    return ""

def parse_op_drop_data(data, chain):
    version = chain.protocol_version
    if version <= 10006:
        func_name = 'parse_op_drop_data_10006'
    else:
        func_name = 'parse_op_drop_data_10007'

    def func_not_found(data):  # just in case we dont have the function
        print "No function found to parse data for protocol version " + str(version)

    func = getattr(sys.modules[__name__], func_name, func_not_found)
    # print "func = ", func
    return func(data)


def parse_op_drop_data_10007(data):
    rettype = OP_DROP_TYPE_UNKNOWN
    retval = None
    # spkn
    # "asm" : "73706b6e01000106646f6c6c617200410464000000 OP_DROP OP_RETURN",
    # "hex" : "1573706b6e01000106646f6c6c617200410464000000756a",
    if data[0:4] == bytearray.fromhex(u'73706b6e'):
        # spkn
        if ord(data[4]) == 0x01:
            rettype = OP_DROP_TYPE_SPKN_NEW_ISSUE
            retval = parse_new_issuance_metadata_10007(data[5:])
        if ord(data[4]) == 0x02:
            rettype = OP_DROP_TYPE_SPKN_CREATE_STREAM
            retval = parse_create_stream_10007(data[5:])
        if ord(data[4]) == 0x10:
            rettype = OP_DROP_TYPE_SPKN_CREATE_UPGRADE
            retval = parse_create_stream_10007(data[5:])
        if ord(data[4]) == 0x11:
            rettype = OP_DROP_TYPE_SPKN_CREATE_FILTER
            retval = parse_create_stream_10007(data[5:])
            del retval["Open to all writers"]

        return rettype, retval
    if data[0:4] == bytearray.fromhex(u'73706b69'):
        # spki
        # example
        #     "scriptPubKey" : {
        #         "asm" : "73706b69000000001976a914dc27f1aeb36b1ec1b94f6f55ffe53fad1f1b0aa588ac OP_DROP OP_RETURN",
        #         "hex" : "2273706b69000000001976a914dc27f1aeb36b1ec1b94f6f55ffe53fad1f1b0aa588ac756a",
        #         "type" : "nulldata"
        #     },
        #     "inputcache" : [
        #         {
        #             "vin" : 0,
        #             "asm" : "OP_DUP OP_HASH160 dc27f1aeb36b1ec1b94f6f55ffe53fad1f1b0aa5 OP_EQUALVERIFY OP_CHECKSIG",
        #             "hex" : "76a914dc27f1aeb36b1ec1b94f6f55ffe53fad1f1b0aa588ac"
        #         }
        #     ],
        cache = {}
        pos = 4
        while pos < len(data):
            (index,) = struct.unpack("<L", data[pos:pos + 4])
            pos += 4

            flen = ord(data[pos:pos + 1])
            pos += 1
            # print "pos of payload: ", pos
            if flen == 253:
                (size,) = struct.unpack('<H', data[pos:pos + 2])
                flen = size
                pos += 2
            elif flen == 254:
                (size,) = struct.unpack('<I', data[pos:pos + 4])
                flen = size
                pos += 4
            elif flen == 255:
                (size,) = struct.unpack('<Q', data[pos:pos + 8])
                flen = size
                pos += 8

            scriptpubkey = data[pos:pos + flen]

            cache[str(index)] = scriptpubkey

            pos += flen

        rettype = OP_DROP_TYPE_SPKI
        retval = cache

        return rettype, retval

    elif data[0:4] == bytearray.fromhex(u'73706b71') or data[0:4] == bytearray.fromhex(u'73706b6f'):
        # spkq or spko
        # prefix: if txid begins ce8a..., 0x8ace = 35534 is the correct prefix.
        assets = []
        pos = 4
        datalen = len(data)
        while (pos + 24) <= datalen:
            txid = long_hex(data[pos:pos + 16][::-1])  # reverse the bytes and resulting hex string
            (quantity,) = struct.unpack("<Q", data[pos + 16:pos + 24])
            assets.append({'assetref': txid, 'quantity': quantity})
            pos += 24

        if data[0:4] == bytearray.fromhex(u'73706b6f'):
            rettype = OP_DROP_TYPE_ISSUE_MORE_ASSET
        else:
            rettype = OP_DROP_TYPE_SEND_ASSET
        retval = assets
        return rettype, retval
    elif data[0:4] == bytearray.fromhex(u'73706b65'):
        # spke, the txid fragment value could could be either a stream txid or an asset txid
        pos = 4
        retvalue = long_hex(data[pos:pos + 16][::-1])  # reverse the bytes and resulting hex string
        rettype = OP_DROP_TYPE_SPKE
        return rettype, retvalue
    elif data[0:4] == bytearray.fromhex(u'73706b75'):
        # spku
        if ord(data[4]) == 0x01:
            # asset = 0x01
            retvalue = parse_follow_on_issuance_metadata_10007(data[5:])
            # "asm" : "73706b658de2f6f31a17419091ab89dcb91fcda8 OP_DROP 73706b75016465736372697074696f6e0004626c6168 OP_DROP OP_RETURN",
            # "hex" : "1473706b658de2f6f31a17419091ab89dcb91fcda8751673706b75016465736372697074696f6e0004626c6168756a",
            # "type" : "nulldata"
            rettype = OP_DROP_TYPE_FOLLOW_ON_ISSUANCE_METADATA  # TODO: Return op_drop type of assetdetails?
            return rettype, retvalue
        # If not 0x01, unknown type of spku
    elif data[:4] == bytearray.fromhex(u'73706b66'):
        rettype = OP_DROP_TYPE_SPKF
        retvalue = None
        return rettype, retvalue

    elif data[:4] == bytearray.fromhex(u'73706b61'):
        # spka
        rettype = OP_DROP_TYPE_SPKN_APPROVE_UPGRADE
        retvalue = bool(data[4])
        return rettype, retvalue

    elif data[:4] == bytearray.fromhex(u'73706b64'):
        # spkd
        rettype = OP_DROP_TYPE_RAW_DATA
        retvalue = data[4:]
        return rettype, retvalue

    # Backwards compatibility: if the op_drop data has not been handled yet, fall through to 10006 parsing
    return parse_op_drop_data_10006(data)


# TODO: Refactor...
def parse_create_stream_10007(data):
    pos = 0
    # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
    fields = dict()

    # If the property 'Open to all writers' is not present, we treat it as false.
    opentoall = "Open to all writers"
    fields[opentoall] = "False"

    while pos < len(data):
        # Is this a special property with meaning only for MultiChain?
        if data[pos:pos + 1] == "\0":
            assetproplen = ord(data[pos + 2:pos + 3])
            assetprop = data[pos + 3:pos + 3 + assetproplen]
            proptype = ord(data[pos + 1])
            # Create stream has special properties
            if proptype == 0x01:
                fields["Name"] = assetprop
            elif proptype == 0x04:
                fields[opentoall] = str(ord(assetprop) == 1)
            elif proptype == 0x05:  # JSON_DETAILS
                fname = "JSON Data"
                try:
                    json_data = ubjson.loadb(assetprop)
                    for k in ('text', 'json'):
                        if k in json_data:
                            json_data = json_data[k]
                            break
                    fields[fname] = render_long_data_with_popover(json.dumps(json_data))
                except ValueError:
                    fields[fname] = long_hex(assetprop)
            elif proptype == 0x06:  # PERMISSIONS
                permission_code, = struct.unpack("<b", assetprop)
                fields[opentoall] = str(permission_code == 0)
            elif proptype in [0x07]:  # RESTRICTIONS
                restriction_code, = struct.unpack("<b", assetprop)
                if restriction_code != 0:
                    restrictions = []
                    if restriction_code == 0x01:
                        restrictions.append("onchain")
                    if restriction_code == 0x02:
                        restrictions.append("offchain")
                    fields["Restrictions"] = ','.join(restrictions)

            # Filter
            elif proptype == 0x45:  # RESTRICTIONS
                pass
            elif proptype == 0x46:  # FILTER CODE
                fields["Code"] = render_long_data_with_popover("<pre>{}</pre>".format(assetprop), hover=False)
            elif proptype == 0x47:  # TYPE
                fname = "Type"
                filter_type = ord(assetprop[0])
                if filter_type == 0x00:
                    fields[fname] = "Transaction"
                elif filter_type == 0x01:
                    fields[fname] = "Stream"
                else:
                    fields[fname] = "Invalid ({})".format(filter_type)

            else:
                fields["Property at offset {0}".format(pos)] = long_hex(assetprop)
            pos = pos + 3 + assetproplen
            continue

        searchdata = data[pos:]
        fname = searchdata[:searchdata.index("\0")]
        pos = pos + len(fname) + 1

        flen = ord(data[pos:pos + 1])
        pos += 1
        # print "pos of payload: ", pos
        if flen == 253:
            (size,) = struct.unpack('<H', data[pos:pos + 2])
            flen = size
            pos += 2
        elif flen == 254:
            (size,) = struct.unpack('<I', data[pos:pos + 4])
            flen = size
            pos += 4
        elif flen == 255:
            (size,) = struct.unpack('<Q', data[pos:pos + 8])
            flen = size
            pos += 8
        fields[fname] = data[pos:pos + flen]
        pos += flen
    return fields


def parse_follow_on_issuance_metadata_10007(data):
    pos = 0
    # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
    fields = dict()
    while pos < len(data):
        # Protocol 10007: there are no special properties for follow on issuance metadata
        if data[pos:pos + 1] == "\0":
            assetproplen = ord(data[pos + 2:pos + 3])
            assetprop = data[pos + 3:pos + 3 + assetproplen]
            proptype = ord(data[pos + 1])
            if proptype == 0x05:  # JSON_DETAILS
                fname = "JSON Data"
                try:
                    json_data = ubjson.loadb(assetprop)
                    for k in ('text', 'json'):
                        if k in json_data:
                            json_data = json_data[k]
                            break
                    fields[fname] = render_long_data_with_popover(json.dumps(json_data))
                except ValueError:
                    fields[fname] = long_hex(assetprop)
            else:
                fname = "MultiChain special property at offset {0}".format(pos)
                fields[fname] = long_hex(assetprop)
            pos = pos + 3 + assetproplen
            continue

        searchdata = data[pos:]
        fname = searchdata[:searchdata.index("\0")]
        pos = pos + len(fname) + 1

        flen = ord(data[pos:pos + 1])
        pos += 1
        # print "pos of payload: ", pos
        if flen == 253:
            (size,) = struct.unpack('<H', data[pos:pos + 2])
            flen = size
            pos += 2
        elif flen == 254:
            (size,) = struct.unpack('<I', data[pos:pos + 4])
            flen = size
            pos += 4
        elif flen == 255:
            (size,) = struct.unpack('<Q', data[pos:pos + 8])
            flen = size
            pos += 8

        fields[fname] = data[pos:pos + flen]
        pos += flen
    return fields


def parse_new_issuance_metadata_10007(data):
    pos = 0
    searchdata = data[pos:]
    # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
    fields = dict()

    # If the property 'Open to follow-on issuance' is not present, we treat it as false.
    opentoissuance = "Open to follow-on issuance"
    fields[opentoissuance] = False

    while pos < len(data):
        # Is this a special property with meaning only for MultiChain?
        if data[pos:pos + 1] == "\0":
            assetproplen = ord(data[pos + 2:pos + 3])
            assetprop = data[pos + 3:pos + 3 + assetproplen]
            proptype = ord(data[pos + 1])
            # Create stream has special properties
            if proptype == 0x01:
                fname = "Asset Name"
                fields[fname] = assetprop
            elif proptype == 0x02:
                fname = opentoissuance
                fields[fname] = bool(ord(assetprop) == 1)
            elif proptype == 0x05:  # JSON_DETAILS
                fname = "JSON Data"
                try:
                    json_data = ubjson.loadb(assetprop)
                    for k in ('text', 'json'):
                        if k in json_data:
                            json_data = json_data[k]
                            break
                    fields[fname] = render_long_data_with_popover(json.dumps(json_data))
                except ValueError:
                    fields[fname] = long_hex(assetprop)
            elif proptype == 0x06:  # RESTRICTIONS
                restriction_code, = struct.unpack("<b", assetprop)
                if restriction_code != 0:
                    fname = "Restrictions"
                    restrictions = []
                    if restriction_code & 0x02:
                        restrictions.append("send")
                    if restriction_code & 0x04:
                        restrictions.append("receive")
                    fields[fname] = ','.join(restrictions)
            elif proptype == 0x41:
                fname = "Quantity Multiple"
                (multiplier,) = struct.unpack("<L", assetprop)
                fields[fname] = multiplier
            else:
                fname = "MultiChain special property at offset {0}".format(pos)
                fields[fname] = long_hex(assetprop)
            pos = pos + 3 + assetproplen
            continue

        searchdata = data[pos:]
        fname = searchdata[:searchdata.index("\0")]
        # print "field name: ", fname, " field name len: ", len(fname)
        pos = pos + len(fname) + 1
        # print "pos of vle: ", pos
        # subdata = subdata[len(fname):]

        flen = ord(data[pos:pos + 1])
        pos += 1
        # print "pos of payload: ", pos
        if flen == 253:
            (size,) = struct.unpack('<H', data[pos:pos + 2])
            flen = size
            pos += 2
        elif flen == 254:
            (size,) = struct.unpack('<I', data[pos:pos + 4])
            flen = size
            pos += 4
        elif flen == 255:
            (size,) = struct.unpack('<Q', data[pos:pos + 8])
            flen = size
            pos += 8
        # print "pos of payload: ", pos
        # print "payload length: ", flen
        fields[fname] = data[pos:pos + flen]
        pos += flen

    return fields


# https://docs.python.org/2/library/struct.html
def parse_op_drop_data_10006(data):
    """
    Return TYPE, DATA where the format of DATA depends on TYPE.

    * OP_DROP_TYPE_ISSUE_ASSET - DATA is the quantity of raw units issued
    * OP_DROP_TYPE_SEND_ASSET  - DATA is a list of dictionary of key values: asset reference, quantity
    * OP_DROP_TYPE_PERMISSION  -  DATA is a dictionary of key values: Permission flags, type (grant/revoke), block range, time
    * OP_DROP_TYPE_CREATE_STREAM - DATA is value of stream type e.g. 0x02
    * OP_DROP_TYPE_OP_DROP_TYPE_STREAM_ITEM - DATA is first 16 bytes of stream creation txid

    :param data:
    :return:
    """
    # print "parse_op_drop_data: = %s" % binascii.hexlify(data)
    rettype = OP_DROP_TYPE_UNKNOWN
    retval = None
    if data[0:4] == bytearray.fromhex(u'73706b67'):  # spkg
        (qty,) = struct.unpack("<Q", data[4:12]);
        rettype = OP_DROP_TYPE_ISSUE_ASSET
        retval = qty
    elif data[0:4] == bytearray.fromhex(u'73706b71') or data[0:4] == bytearray.fromhex(u'73706b6f'):
        # spkq, spko
        # prefix: if txid begins ce8a..., 0x8ace = 35534 is the correct prefix.
        assets = []
        pos = 4
        datalen = len(data)
        while (pos + 18) <= datalen:
            (block, offset, prefix, quantity) = struct.unpack("<LLHQ", data[pos:pos + 18])
            assetref = "%d-%d-%d" % (block, offset, prefix)
            # print "ASSET SENT %d-%d-%d QTY %d" % (block,offset,prefix,quantity)
            assets.append({'assetref': assetref, 'quantity': quantity})
            pos += 18
        if data[0:4] == bytearray.fromhex(u'73706b6f'):
            # spko
            rettype = OP_DROP_TYPE_ISSUE_MORE_ASSET
        else:
            rettype = OP_DROP_TYPE_SEND_ASSET
        retval = assets
    elif data[0:4] == bytearray.fromhex(u'73706b70'):
        # spkp (for regular permissions and stream permissions)
        # 4 byte bitmap uint32, uint32 from, unit32 to, uint32 timestamp
        # bitmap connect=1, send=2, receive=4, issue=16, mine=256, admin=4096.
        (bitmap, block_from, block_to, timestamp) = struct.unpack("<LLLL", data[4:])
        revoke = True if block_from == 0 and block_to == 0 else False
        # print "op_drop payload is ", long_hex(data[4:])
        # print "bitmap %s, %d-%d, time %d" % (str(bin(bitmap))[2:], block_from, block_to, timestamp)
        # literal d = {'x':obj}
        connect = (bitmap & 0x00000001) > 0
        send = (bitmap & 0x00000002) > 0
        receive = (bitmap & 0x00000004) > 0
        write = (bitmap & 0x00000008) > 0
        issue = (bitmap & 0x00000010) > 0
        create = (bitmap & 0x00000020) > 0
        mine = (bitmap & 0x00000100) > 0
        high1 = (bitmap & 0x00000200) > 0
        high2 = (bitmap & 0x00000400) > 0
        high3 = (bitmap & 0x00000800) > 0
        admin = (bitmap & 0x00001000) > 0
        activate = (bitmap & 0x00002000) > 0
        upgrade = (bitmap & 0x00010000) > 0
        low1 = (bitmap & 0x00020000) > 0
        low2 = (bitmap & 0x00040000) > 0
        low3 = (bitmap & 0x00080000) > 0
        filter = (bitmap & 0x04000000) > 0
        rettype = OP_DROP_TYPE_PERMISSION
        retval = {'connect': connect, 'send': send, 'receive': receive, 'write': write, 'issue': issue,
                  'create': create, 'mine': mine, 'high1': high1, 'high2': high2, 'high3': high3, 'admin': admin,
                  'activate': activate, 'upgrade': upgrade, 'low1': low1, 'low2': low2, 'low3': low3,  'filter': filter,
                  'type': 'revoke' if revoke is True else 'grant',
                  'startblock': block_from, 'endblock': block_to}
    elif data[0:4] == bytearray.fromhex(u'73706b6e'):
        # spkn
        # "asm": "73706b6e02 OP_DROP OP_RETURN 53504b6300010873747265616d3100",
        # "hex": "0573706b6e02756a0f53504b6300010873747265616d3100",

        # entity type must be 0x02 (stream)
        if ord(data[4]) == 0x02:
            rettype = OP_DROP_TYPE_CREATE_STREAM
            retval = ord(data[4])
    elif data[0:4] == bytearray.fromhex(u'73706b65'):
        # SPKc
        # "asm": "73706b650e869894bc77452a9c8eeb2d9391a217 OP_DROP 73706b6b6b657931 OP_DROP OP_RETURN 2232576",
        # "hex": "1473706b650e869894bc77452a9c8eeb2d9391a217750873706b6b6b657931756a03001122",
        rettype = OP_DROP_TYPE_STREAM_ITEM
        retval = long_hex(data[4:20][::-1])  # reverse the bytes and resulting hex string
    return rettype, retval


def parse_op_return_data(data, chain):
    version = chain.protocol_version
    if version <= 10006:
        func_name = 'parse_op_return_data_10006'
    else:
        func_name = 'parse_op_return_data_10007'

    def func_not_found(data):  # just in case we dont have the function
        print "No function found to parse data for protocol version " + str(version)

    func = getattr(sys.modules[__name__], func_name, func_not_found)
    # print "func = ", func
    return func(data)


def parse_op_return_data_10007(data):
    return parse_op_return_data_10006(data)


def parse_op_return_data_10006(data):
    """
    Return TYPE, DATA where the format of DATA depends on TYPE.

    * OP_RETURN_TYPE_ISSUE_ASSET  - DATA is a dictionary of key values: multiplier, name

    :param data:
    :return:
    """
    rettype = OP_RETURN_TYPE_UNKNOWN
    retval = None
    if data[0:4] == bytearray.fromhex(u'53504b61'):  # SPKa
        (multiplier,) = struct.unpack("<L", data[4:8])
        pos = 8
        searchdata = data[pos:]
        assetname = searchdata[:searchdata.index("\0")]
        pos = pos + len(assetname) + 1

        # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
        fields = dict()
        while pos < len(data):
            searchdata = data[pos:]

            # Is this a special property with meaning only for MultiChain?
            if data[pos:pos + 1] == "\0":
                assetproplen = ord(data[pos + 2:pos + 3])
                assetprop = data[pos + 3:pos + 3 + assetproplen]
                if data[pos + 1] == "\x02":
                    # Asset property
                    fields['open'] = str(bool(ord(data[pos + 3:pos + 4])))
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
            # subdata = subdata[len(fname):]

            flen = ord(data[pos:pos + 1])
            pos += 1
            # print "pos of payload: ", pos
            if flen == 253:
                (size,) = struct.unpack('<H', data[pos:pos + 2])
                flen = size
                pos += 2
            elif flen == 254:
                (size,) = struct.unpack('<I', data[pos:pos + 4])
                flen = size
                pos += 4
            elif flen == 255:
                (size,) = struct.unpack('<Q', data[pos:pos + 8])
                flen = size
                pos += 8
            # print "pos of payload: ", pos
            # print "payload length: ", flen
            fields[fname] = data[pos:pos + flen]
            pos += flen

        rettype = OP_RETURN_TYPE_ISSUE_ASSET
        retval = {'multiplier': multiplier, 'name': str(assetname), 'fields': fields}
    elif data[0:4] == bytearray.fromhex(u'53504b62'):  # SPKb
        rettype = OP_RETURN_TYPE_MINER_BLOCK_SIGNATURE
        retval = data[4:]
    elif data[0:4] == bytearray.fromhex(u'53504b63'):  # SPKc
        pos = 4
        searchdata = data[pos:]
        # Multiple fields follow: field name (null delimited), variable length integer, raw data of field
        fields = dict()

        # If the property 'Open to all writers' is not present, we treat it as false.
        opentoall = "Open to all writers"
        fields[opentoall] = "False"

        while pos < len(data):
            # Is this a special property with meaning only for MultiChain?
            if data[pos:pos + 1] == "\0":
                assetproplen = ord(data[pos + 2:pos + 3])
                assetprop = data[pos + 3:pos + 3 + assetproplen]
                proptype = ord(data[pos + 1])
                # Create stream has special properties
                if proptype == 0x01:
                    fname = "Name"
                    fields[fname] = assetprop
                elif proptype == 0x04:
                    fname = opentoall
                    if ord(assetprop) == 1:
                        fields[fname] = "True"
                    else:
                        fields[fname] = "False"
                else:
                    fname = "Property at offset {0}".format(pos)
                    fields[fname] = long_hex(assetprop)
                pos = pos + 3 + assetproplen
                continue

            searchdata = data[pos:]
            fname = searchdata[:searchdata.index("\0")]
            # print "field name: ", fname, " field name len: ", len(fname)
            pos = pos + len(fname) + 1
            # print "pos of vle: ", pos
            # subdata = subdata[len(fname):]

            flen = ord(data[pos:pos + 1])
            pos += 1
            # print "pos of payload: ", pos
            if flen == 253:
                (size,) = struct.unpack('<H', data[pos:pos + 2])
                flen = size
                pos += 2
            elif flen == 254:
                (size,) = struct.unpack('<I', data[pos:pos + 4])
                flen = size
                pos += 4
            elif flen == 255:
                (size,) = struct.unpack('<Q', data[pos:pos + 8])
                flen = size
                pos += 8
            # print "pos of payload: ", pos
            # print "payload length: ", flen
            fields[fname] = data[pos:pos + flen]
            pos += flen
        rettype = OP_RETURN_TYPE_SPKC
        retval = {'multiplier': None, 'name': None, 'fields': fields}
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
        data = decoded[3][1]  # 4th element contains the OP_DROP data.
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_STREAM_ITEM_TEMPLATE):
        data = decoded[0][1]  # 1st element contains the creation txid OP_DROP data
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_STREAM_FORMATTED_ITEM_TEMPLATE):
        data = decoded[0][1]  # 1st element contains the creation txid OP_DROP data
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_STREAM_TEMPLATE):
        data = decoded[0][1]  # 1st element contains the OP_DROP data.
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_SPKN_TEMPLATE):
        data = decoded[0][1]  # 1st element contains the OP_DROP data.
    elif deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_FOLLOW_ON_ISSUANCE_METADATA_TEMPLATE):
        data = decoded[0][1]  # 1st element contains the OP_DROP data.
    elif len(decoded) >= 3 and decoded[-2][1] and decoded[-2][1].startswith("spkq"):
        data = decoded[-2][1] # element before last contains the OP_DROP data.
    return data


def get_multichain_op_return_data(script):
    """
    Get OP_RETURN data.
    :param script: script byte data
    :return:
    """
    try:
        decoded = [x for x in deserialize.script_GetOp(script)]
    except Exception:
        return None
    data = None
    if deserialize.match_decoded(decoded, Chain.SCRIPT_MULTICHAIN_STREAM_TEMPLATE):
        data = decoded[3][1]  # 4th element contains the OP_RETURN data.
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
    # s = "{:.20f}".format(1.0/multiple) #str(1.0/multiple)
    # p = s[::-1].find('.')

    # assume base 10 to keep things simple
    p = len(str(multiple)) - 1

    if p is 0:
        fmt = "{0:d}"
        v = int(rawqty)
    else:
        fmt = "{0:." + "{0}".format(p) + "f}"
        v = float(rawqty) / float(multiple)
    return fmt.format(v)


def is_printable(s):
    """
    Return True if the string is ASCII (with punctuation) and printable
    :param s:
    :return:
    """
    for c in s:
        if c not in string.printable:
            return False
    return True


def is_hexadecimal(s):
    return all(c in string.hexdigits for c in s)


# MULTICHAIN END


def render_long_data_with_popover(data, limit=40, classes="", hover=True):
    """
    Render a string, potentially truncating and enabling a popover with the full data triggered by clicking
    on the ellipses at the end of the value.

    If @p classes are given, wrap the value in a span.

    :param data:    The string to render.
    :param limit:   The length at which to truncate the data.
    :param classes: Additional CSS classes for the returned tag.
    :param hover:   Popover activated by hover or click.
    :return:        The HTML to render for the data.
    """
    data_html = data
    if data_html.startswith("<pre>"):
        data_html = data_html[5:]
    if data_html.endswith("</pre>"):
        data_html = data_html[:-6]
    data_len = len(data_html)
    data_html = escape(data_html[:limit], quote=True)
    if data_len > limit:
        trigger = "hover" if hover else "focus"
        tabindex = None if hover else ' tabindex="0"'
        data_html = '{}<span class="ellipses" data-toggle="popover" data-trigger="{}"{} data-content=" {} ">...</span>'.format(
            data_html, trigger, tabindex, escape(data, quote=True))
    if classes:
        data_html = '<span class="{}">{}</span>'.format(classes, data_html)
    return data_html


def render_long_data_with_link(data, data_ref, limit=40, classes=""):
    """
    Render a hex string, potentially truncating and enabling a link to the full data by clicking
    on the ellipses at the end of the value.

    If @p classes are given, wrap the value in a span.

    :param data:     The hex string to render.
    :param data_ref: The link to the full data.
    :param limit:    The length at which to truncate the data.
    :param classes:  Additional CSS classes for the returned tag.
    :return:         The HTML to render for the data.
    """
    data_html = escape(data[:limit], quote=True)
    if len(data) > limit:
        data_html = '{}:{} <a class="ellipses" title="Click to show all data" href="{}">...</a>'.format(
            len(data) / 2, data_html, data_ref)
    if classes:
        data_html = '<span class="{}">{}</span>'.format(classes, data_html)
    return data_html
