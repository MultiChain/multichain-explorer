# Copyright(C) 2014 by Abe developers.

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

from .. import deserialize, BCDataStream, util
from ..deserialize import opcodes

def create(policy, **kwargs):
    mod = __import__(__name__ + '.' + policy, fromlist=[policy])
    cls = getattr(mod, policy)
    return cls(policy=policy, **kwargs)


PUBKEY_HASH_LENGTH = 20
MAX_MULTISIG_KEYS = 3

# MULTICHAIN START
# Template to match a MultiChain permission or asset transaction which puts a payload before OP_DROP
SCRIPT_MULTICHAIN_TEMPLATE = [
    opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG, opcodes.OP_PUSHDATA4, opcodes.OP_DROP ]

# Template to match a MultiChain entity permission command
SCRIPT_MULTICHAIN_ENTITY_PERMISSION_TEMPLATE = [
    opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG, opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_PUSHDATA4, opcodes.OP_DROP ]

# Template to match a MultiChain stream item
# spke for stream item
SCRIPT_MULTICHAIN_STREAM_ITEM_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_RETURN, opcodes.OP_PUSHDATA4 ]
# spkf for stream item
SCRIPT_MULTICHAIN_STREAM_FORMATTED_ITEM_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_RETURN, opcodes.OP_PUSHDATA4 ]

# spke for asset
SCRIPT_MULTICHAIN_FOLLOW_ON_ISSUANCE_METADATA_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_RETURN]

# Template to match a MultiChain create stream command
# or spkf for asset item
SCRIPT_MULTICHAIN_STREAM_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_RETURN, opcodes.OP_PUSHDATA4 ]

# TODO: Rename as the template also matches spki for input cache
# spkn, for both new issue and create stream
SCRIPT_MULTICHAIN_SPKN_TEMPLATE = [opcodes.OP_PUSHDATA4, opcodes.OP_DROP, opcodes.OP_RETURN ]

# Matches all opcodes < PUSHDATA4
# See: https://en.bitcoin.it/wiki/Script
SCRIPT_MULTICHAIN_OP_RETURN_TEMPLATE = [ opcodes.OP_RETURN, opcodes.OP_PUSHDATA4 ]

# Template to match a MultiChain asset pay-to-script-hash (P2SH) output script
# e.g. "OP_HASH160 f1191c44953b7da866dba982d155bbd8eeb89dfc OP_EQUAL 73706b7104000000f70200001ae41027000000000000 OP_DROP"
SCRIPT_MULTICHAIN_P2SH_TEMPLATE = [ opcodes.OP_HASH160, PUBKEY_HASH_LENGTH, opcodes.OP_EQUAL, opcodes.OP_PUSHDATA4, opcodes.OP_DROP]

# MULTICHAIN END

# Template to match a pubkey hash ("Bitcoin address transaction") in
# txout_scriptPubKey.  OP_PUSHDATA4 matches any data push.
SCRIPT_ADDRESS_TEMPLATE = [
    opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]

# Template to match a pubkey ("IP address transaction") in txout_scriptPubKey.
SCRIPT_PUBKEY_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]

# Template to match a BIP16 pay-to-script-hash (P2SH) output script.
SCRIPT_P2SH_TEMPLATE = [ opcodes.OP_HASH160, PUBKEY_HASH_LENGTH, opcodes.OP_EQUAL ]

# Template to match a script that can never be redeemed, used in Namecoin.
SCRIPT_BURN_TEMPLATE = [ opcodes.OP_RETURN ]

SCRIPT_TYPE_INVALID = 0
SCRIPT_TYPE_UNKNOWN = 1
SCRIPT_TYPE_PUBKEY = 2
SCRIPT_TYPE_ADDRESS = 3
SCRIPT_TYPE_BURN = 4
SCRIPT_TYPE_MULTISIG = 5
SCRIPT_TYPE_P2SH = 6
# MULTICHAIN START
SCRIPT_TYPE_MULTICHAIN = 7
SCRIPT_TYPE_MULTICHAIN_OP_RETURN = 8
SCRIPT_TYPE_MULTICHAIN_P2SH = 9
SCRIPT_TYPE_MULTICHAIN_STREAM = 10
SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM = 11
SCRIPT_TYPE_MULTICHAIN_ENTITY_PERMISSION = 12
SCRIPT_TYPE_MULTICHAIN_SPKN = 13
SCRIPT_TYPE_MULTICHAIN_SPKU = 14    # follow on asset issuance metadata
SCRIPT_TYPE_MULTICHAIN_SPKF = 15
SCRIPT_TYPE_MULTICHAIN_APPROVE = 16
SCRIPT_TYPE_MULTICHAIN_FILTER = 17
# MULTICHAIN END


class BaseChain(object):
# MULTICHAIN START
    POLICY_ATTRS = ['magic', 'name', 'code3', 'address_checksum', 'address_version', 'decimals', 'script_addr_vers', 'protocol_version']
# MULTICHAIN END
    __all__ = ['id', 'policy'] + POLICY_ATTRS

    def __init__(chain, src=None, **kwargs):
        for attr in chain.__all__:
            if attr in kwargs:
                val = kwargs.get(attr)
            elif hasattr(chain, attr):
                continue
            elif src is not None:
                val = getattr(src, attr)
            else:
                val = None
            setattr(chain, attr, val)

    def has_feature(chain, feature):
        return False

    def ds_parse_block_header(chain, ds):
        return deserialize.parse_BlockHeader(ds)

    def ds_parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds)

    def ds_parse_block(chain, ds):
        d = chain.ds_parse_block_header(ds)
        d['transactions'] = []
        nTransactions = ds.read_compact_size()
        for i in xrange(nTransactions):
            d['transactions'].append(chain.ds_parse_transaction(ds))
        return d

    def ds_serialize_block(chain, ds, block):
        chain.ds_serialize_block_header(ds, block)
        ds.write_compact_size(len(block['transactions']))
        for tx in block['transactions']:
            chain.ds_serialize_transaction(ds, tx)

    def ds_serialize_block_header(chain, ds, block):
        ds.write_int32(block['version'])
        ds.write(block['hashPrev'])
        ds.write(block['hashMerkleRoot'])
        ds.write_uint32(block['nTime'])
        ds.write_uint32(block['nBits'])
        ds.write_uint32(block['nNonce'])

    def ds_serialize_transaction(chain, ds, tx):
        ds.write_int32(tx['version'])
        ds.write_compact_size(len(tx['txIn']))
        for txin in tx['txIn']:
            chain.ds_serialize_txin(ds, txin)
        ds.write_compact_size(len(tx['txOut']))
        for txout in tx['txOut']:
            chain.ds_serialize_txout(ds, txout)
        ds.write_uint32(tx['lockTime'])

    def ds_serialize_txin(chain, ds, txin):
        ds.write(txin['prevout_hash'])
        ds.write_uint32(txin['prevout_n'])
        ds.write_string(txin['scriptSig'])
        ds.write_uint32(txin['sequence'])

    def ds_serialize_txout(chain, ds, txout):
        ds.write_int64(txout['value'])
        ds.write_string(txout['scriptPubKey'])

    def serialize_block(chain, block):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_block(ds, block)
        return ds.input

    def serialize_block_header(chain, block):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_block_header(ds, block)
        return ds.input

    def serialize_transaction(chain, tx):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_transaction(ds, tx)
        return ds.input

    def ds_block_header_hash(chain, ds):
        return chain.block_header_hash(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

    def transaction_hash(chain, binary_tx):
        return util.double_sha256(binary_tx)

    def merkle_hash(chain, hashes):
        return util.double_sha256(hashes)

    # Based on CBlock::BuildMerkleTree().
    def merkle_root(chain, hashes):
        while len(hashes) > 1:
            size = len(hashes)
            out = []
            for i in xrange(0, size, 2):
                i2 = min(i + 1, size - 1)
                out.append(chain.merkle_hash(hashes[i] + hashes[i2]))
            hashes = out
        return hashes and hashes[0]

    def parse_block_header(chain, header):
        return chain.ds_parse_block_header(util.str_to_ds(header))

    def parse_transaction(chain, binary_tx):
        return chain.ds_parse_transaction(util.str_to_ds(binary_tx))

    def is_coinbase_tx(chain, tx):
        return len(tx['txIn']) == 1 and tx['txIn'][0]['prevout_hash'] == chain.coinbase_prevout_hash

    coinbase_prevout_hash = util.NULL_HASH
    coinbase_prevout_n = 0xffffffff
    genesis_hash_prev = util.GENESIS_HASH_PREV

    def parse_txout_script(chain, script):
        """
        Return TYPE, DATA where the format of DATA depends on TYPE.

        * SCRIPT_TYPE_INVALID  - DATA is the raw script
        * SCRIPT_TYPE_UNKNOWN  - DATA is the decoded script
        * SCRIPT_TYPE_PUBKEY   - DATA is the binary public key
        * SCRIPT_TYPE_ADDRESS  - DATA is the binary public key hash
        * SCRIPT_TYPE_BURN     - DATA is None
        * SCRIPT_TYPE_MULTISIG - DATA is {"m":M, "pubkeys":list_of_pubkeys}
        * SCRIPT_TYPE_P2SH     - DATA is the binary script hash
# MULTICHAIN START
        * SCRIPT_TYPE_MULTICHAIN - DATA is the binary public key (there is another method to get the OPDROP data)
        * SCRIPT_TYPE_MULTICHAIN_P2SH - DATA is the binary script hash (there is another method to get the OPDROP data)
        * SCRIPT_TYPE_MULTICHAIN_STREAM - DATA is a dicationary containing op_drop and op_return data.
        * SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM - Data is a dictionary containing stream creation txid, item key, item data.
        * SCRIPT_TYPE_MULTICHAIN_STREAM_PERMISSION - Data is a dictionary containing stream creation txid, permissions, pubkey_hash
        * SCRIPT_TYPE_MULTICHAIN_SPKN
        * SCRIPT_TYPE MULTICHAIN_SPKE
        * SCRIPT_TYPE_MULTICHAIN_SPKF - DATA is the formatted metadata
# MULTICHAIN END
        """
        if script is None:
            raise ValueError()
        try:
            decoded = [ x for x in deserialize.script_GetOp(script) ]
        except Exception:
            return SCRIPT_TYPE_INVALID, script
        return chain.parse_decoded_txout_script(decoded)

    def parse_decoded_txout_script(chain, decoded):
# MULTICHAIN START
        # Return dict
        if deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_ENTITY_PERMISSION_TEMPLATE):
            if decoded[7][1].startswith("spkp"):
                dict = {"txid":decoded[5][1], "permissions":decoded[7][1], "pubkey_hash":decoded[2][1]}
                return SCRIPT_TYPE_MULTICHAIN_ENTITY_PERMISSION, dict


        # Return script type and address
        if deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_TEMPLATE):
            pubkey_hash = decoded[2][1]
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_MULTICHAIN, pubkey_hash

        # Send asset (perhaps with data)
        if len(decoded) >= 3 and decoded[-2][1] and decoded[-2][1].startswith("spkq"):
            pubkey_hash = decoded[2][1]
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_MULTICHAIN, pubkey_hash

        if len(decoded) >= 6 and decoded[2][1].startswith("spkk"):
            txid = decoded[0][1]
            itemkeys = []
            pos = 2
            while decoded[pos][1] and decoded[pos][1].startswith("spkk"):
                itemkeys.append(decoded[pos][1])
                pos += 2
            itemdata = decoded[:-1][1]
            d = {"streamtxid": txid, "itemkeys": itemkeys, "itemdata":itemdata}
            return SCRIPT_TYPE_MULTICHAIN_STREAM_ITEM, d

        # Return dict
        if deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_STREAM_TEMPLATE):
            drop_data = decoded[0][1]
            if drop_data[:4] == "spkf":
                script_type = SCRIPT_TYPE_MULTICHAIN_SPKF
            else:
                script_type = SCRIPT_TYPE_MULTICHAIN_STREAM
            dict = {"op_drop": drop_data, "op_return": decoded[3][1]}
            return script_type, dict

        if deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_FOLLOW_ON_ISSUANCE_METADATA_TEMPLATE):
            # Could also be upgrade approval.
            if decoded[2][1].startswith("spka"):
                dict = {"upgradeid": decoded[0][1], "approved": decoded[2][1]}
                return SCRIPT_TYPE_MULTICHAIN_APPROVE, dict
            else:
                dict = {"assetidentifier":decoded[0][1], "assetdetails":decoded[2][1]}
                return SCRIPT_TYPE_MULTICHAIN_SPKU, dict

        #SCRIPT_MULTICHAIN_SPKN_TEMPLATE
        if deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_SPKN_TEMPLATE):
            metadata = decoded[0][1]
            return SCRIPT_TYPE_MULTICHAIN_SPKN, metadata

        # Return script type and metadata byte array
        elif deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_OP_RETURN_TEMPLATE):
            metadata = decoded[1][1]
            return SCRIPT_TYPE_MULTICHAIN_OP_RETURN, metadata

        # Return script type and script hash
        elif deserialize.match_decoded(decoded, SCRIPT_MULTICHAIN_P2SH_TEMPLATE):
            script_hash = decoded[1][1]
            assert len(script_hash) == PUBKEY_HASH_LENGTH
            return SCRIPT_TYPE_MULTICHAIN_P2SH, script_hash

# MULTICHAIN END

        elif deserialize.match_decoded(decoded, SCRIPT_ADDRESS_TEMPLATE):
            pubkey_hash = decoded[2][1]
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_ADDRESS, pubkey_hash

        elif deserialize.match_decoded(decoded, SCRIPT_PUBKEY_TEMPLATE):
            pubkey = decoded[0][1]
            return SCRIPT_TYPE_PUBKEY, pubkey

        elif deserialize.match_decoded(decoded, SCRIPT_P2SH_TEMPLATE):
            script_hash = decoded[1][1]
            assert len(script_hash) == PUBKEY_HASH_LENGTH
            return SCRIPT_TYPE_P2SH, script_hash

        elif deserialize.match_decoded(decoded, SCRIPT_BURN_TEMPLATE):
            return SCRIPT_TYPE_BURN, None

        elif len(decoded) >= 4 and decoded[-1][0] == opcodes.OP_CHECKMULTISIG:
            # cf. bitcoin/src/script.cpp:Solver
            n = decoded[-2][0] + 1 - opcodes.OP_1
            m = decoded[0][0] + 1 - opcodes.OP_1
            if 1 <= m <= n <= MAX_MULTISIG_KEYS and len(decoded) == 3 + n and \
                    all([ decoded[i][0] <= opcodes.OP_PUSHDATA4 for i in range(1, 1+n) ]):
                return SCRIPT_TYPE_MULTISIG, \
                    { "m": m, "pubkeys": [ decoded[i][1] for i in range(1, 1+n) ] }

        # Namecoin overrides this to accept name operations.
        return SCRIPT_TYPE_UNKNOWN, decoded

    def pubkey_hash(chain, pubkey):
        return util.pubkey_to_hash(pubkey)

    def script_hash(chain, script):
        return chain.pubkey_hash(script)

    datadir_conf_file_name = "bitcoin.conf"
    datadir_rpcport = 8332
