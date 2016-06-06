#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Virtualchain
    
    Virtualchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Virtualchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Virtualchain.  If not, see <http://www.gnu.org/licenses/>.
"""

from .nulldata import get_nulldata, has_nulldata
from .scripts import *
from .opcodes import *
import traceback

import sys
import os

libdir = os.path.abspath(os.path.dirname(__file__) + "../../..")
sys.path.insert(0, libdir)

from config import MULTIPROCESS_RPC_RETRY, get_logger
from workpool import multiprocess_blockchain_client, multiprocess_batch_size, multiprocess_rpc_marshal, Workpool, multiprocess_blockchain_opts
from hash import bin_double_sha256
from merkle import MerkleTree
from transactions import VirtualOutput, VirtualInput, VirtualDataOutput, VirtualPaymentOutput, VirtualTransaction

import time
import types
import random
import copy
import bitcoin
import binascii
import json
import pprint
from decimal import *
import cPickle as pickle

from bitcoinrpc.authproxy import JSONRPCException

import session
log = get_logger("virtualchain")

UINT_MAX = 2**32-1

# fee defaults
STANDARD_FEE = 1000  # 1000 satoshis = 10 bits = .01 mbits = .00001 BTC
OP_RETURN_FEE = 10000  # 10k satoshis = .0001 BTC

def get_bitcoind( bitcoind_or_opts ):
   """
   Given either a bitcoind API endpoint proxy, 
   or a dictionary of options to generate one in a
   process-local context, return a bitcoind API endpoint 
   proxy.
   """ 
   
   if type(bitcoind_or_opts) == types.DictType or bitcoind_or_opts is None:

      # instantiate from options
      if bitcoind_or_opts is None:
          bitcoind_or_opts = multiprocess_blockchain_opts()

      return multiprocess_blockchain_client( bitcoind_or_opts )
   
   else:
      # already an endpoint 
      return bitcoind_or_opts
   
   
def get_bitcoind_opts( bitcoind_or_opts ):
   """
   Given either a bitcoind API endpoint proxy,
   or a dict of options, generate the set of options.
   """
   if bitcoind_or_opts is None:
      return None 
   
   if type(bitcoind_or_opts) == types.DictType:
      return bitcoind_or_opts
   
   else:
      return bitcoind_or_opts.opts 
   

def indexer_rpc_dispatch( method_name, method_args ):
   """
   Worker subprocess: dispatch a method call from the 
   main indexer process and get the result.
   """

   raise Exception("Should not reach this method")
   if method_name == "getrawtransaction":

       if len(method_args) != 3:
           log.error("getrawtransaction: Invalid argument list")
           return {"error": "getrawtransaction: Invalid argument list"}

       result = getrawtransaction( method_args[0], method_args[1], verbose=method_args[2] )
 
   elif method_name == "getblockhash":
       
       if len(method_args) != 3:
           log.error("getblockhash: Invalid argument list")
           return {"error": "getblockhash: Invalid argument list"}

       result = getblockhash( method_args[0], method_args[1], reset=method_args[2] )

   elif method_name == "getblock":
       
       if len(method_args) != 2:
           log.error("getblock: Invalid argument list")
           return {"error": "getblock: Invalid argument list"}

       result = getblock( method_args[0], method_args[1] )

   else:

       log.error("Unrecognized method")
       return {"error": "Unrecognized method"}

   return result


def getrawtransaction( bitcoind_or_opts, txid, verbose=0 ):
   """
   Get a raw transaction by txid.
   Only call out to bitcoind if we need to.
   """
   
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )

   if bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         
         try:
            
            tx = bitcoind.getrawtransaction( txid, verbose )
            
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je
            
            bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
            continue

         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
        
            bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
            continue 
            
         return tx 
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e 
         continue

   if exc_to_raise is not None:
      # tried as many times as we dared, so bail 
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)



def getrawtransaction_async( workpool, bitcoind_opts, tx_hash, verbose ):
   """
   Get a block transaction, asynchronously, using the pool of processes
   to go get it.
   """

   payload = multiprocess_rpc_marshal( "getrawtransaction", [None, tx_hash, verbose] )

   # log.debug("getrawtransaction_async %s" % tx_hash)
   tx_future = workpool.apply_async( payload )

   return tx_future


def getblockhash( bitcoind_or_opts, block_number, reset ):
   """
   Get a block's hash, given its ID.
   Return None if there are no options
   """
  

   exc_to_raise = None  # exception to raise if we fail
   bitcoind = get_bitcoind( bitcoind_or_opts )
   
   if not reset and bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
       
   if reset:
       new_opts = get_bitcoind_opts( bitcoind_or_opts )
       bitcoind = multiprocess_blockchain_client( new_opts, reset=True )
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         
         try:
         
            block_hash = bitcoind.getblockhash( block_number )
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je 
        
            bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
            continue
         
         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
            
            bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
            continue 
         
         return block_hash
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e
         continue
   
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   

def getblockhash_async( workpool, bitcoind_opts, block_number, reset=False ):
   """
   Get a block's hash, asynchronously, given its ID
   Return a future to the block hash 
   """
 
   payload = multiprocess_rpc_marshal( "getblockhash", [None, block_number, reset] )

   log.debug("Get block hash for %s" % block_number)
   block_hash_future = workpool.apply_async( payload )
   
   return block_hash_future


def getblock( bitcoind_or_opts, block_hash ):
   """
   Get a block's data, given its hash.
   """
   
   bitcoind = get_bitcoind( bitcoind_or_opts )
   if bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
    
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )
   attempts = 0
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      
      try:
         block_data = bitcoind.getblock( block_hash )
         
      except JSONRPCException, je:
         log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
         exc_to_raise = je
     
         attempts += 1
         
         # probably a transient bitcoind failure
         # exponential backof with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
         continue
     
      except Exception, e:
         log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
         exc_to_raise = e
     
         attempts += 1
         
         # probably a transient network failure
         # exponential backoff with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
         continue
   
      return block_data 
      
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   


def getblock_async( workpool, bitcoind_opts, block_hash ):
   """
   Get a block's data, given its hash.
   Return a future to the data.
   """

   payload = multiprocess_rpc_marshal( "getblock", [None, block_hash] )

   log.debug("Get block %s" % block_hash)
   block_future = workpool.apply_async( payload )
   return block_future 


def getblockcount( bitcoind_or_opts ):
   """
   Get the blockchain's current height
   """

   bitcoind = get_bitcoind( bitcoind_or_opts )
   if bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
    
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )
   attempts = 0
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      
      try:
         num_blocks = bitcoind.getblockcount()
         
      except JSONRPCException, je:
         log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
         exc_to_raise = je
     
         attempts += 1
         
         # probably a transient bitcoind failure
         # exponential backof with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
         continue
     
      except Exception, e:
         log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
         exc_to_raise = e
     
         attempts += 1
         
         # probably a transient network failure
         # exponential backoff with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_blockchain_client( bitcoind.opts, reset=True)
         continue
   
      return num_blocks 
      
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
  

def get_output_from_tx( tx, output_index ):
   """
   Given a transaction, get information about a
   particular output.

   @tx: the transaction
   @output_index: the index into the vout
   
   Return a VirtualPaymentOutput with the output fields
   """
   
   # grab the previous tx output (the current input)
   try:
      prev_tx_output = tx['vout'][output_index]
   except Exception, e:
      print >> sys.stderr, "output_index = '%s'" % output_index
      raise e

   # make sure the previous tx output is valid
   if not ('scriptPubKey' in prev_tx_output and 'value' in prev_tx_output):
      return (None, None)

   # extract the script_pubkey
   script_pubkey = prev_tx_output['scriptPubKey']
   
   # build and append the sender to the list of senders
   amount_in = int(prev_tx_output['value']*10**8)
   extra_fields = {
      "script_pubkey": script_pubkey.get('hex'),
      "script_type": script_pubkey.get('type'),
      "script_asm": script_pubkey.get('asm')
   }

   sender = VirtualPaymentOutput( script_pubkey['hex'], amount_in, script_pubkey.get('addresses'), **extra_fields )
   return sender
 

def process_nulldata_tx_async( workpool, bitcoind_opts, tx ):
    """
    Given a transaction and a block hash, begin fetching each 
    of the transaction's vin's transactions.  The reason being,
    we want to acquire each input's nulldata, and for that, we 
    need the raw transaction data for the input.
    
    However, in order to preserve the (sender, tx) relation, we need to 
    preserve the order in which the input transactions occurred.
    To do so, we tag each future with the index into the transaction's 
    vin list, so once the futures have been finalized, we'll have an 
    ordered list of input transactions that is in the same order as 
    they are in the given transaction's vin.
    
    Returns: [(input_idx, tx_fut, tx_output_index)]
    """
    
    tx_futs = []
    senders = []
    total_in = 0
    
    if not ('vin' in tx and 'vout' in tx and 'txid' in tx):
        return None

    inputs = tx['vin']
    
    for i in xrange(0, len(inputs)):
      input = inputs[i]
      
      # make sure the input is valid
      if not ('txid' in input and 'vout' in input):
         continue
      
      # get the tx data for the specified input
      tx_hash = input['txid']
      tx_output_index = input['vout']
      
      tx_fut = getrawtransaction_async( workpool, bitcoind_opts, tx_hash, 1 )
      tx_futs.append( (i, tx_fut, tx_output_index) )
    
    return tx_futs 


def future_next( fut_records, fut_inspector ):
   """
   Find and return a record in a list of records, whose 
   contained future (obtained by the callable fut_inspector)
   is ready and has data to be gathered.
   
   If no such record exists, then select one and block on it
   until its future has data.
   """
   
   if len(fut_records) == 0:
      return None 
  
   
   for fut_record in fut_records:
      fut = fut_inspector( fut_record )
      if fut is not None:
         if fut.ready():
            fut_records.remove( fut_record )
            return fut_record 
   
   # no ready futures.  wait for one
   i = 0
   while True:
       fut_record = fut_records[i % len(fut_records)]
       i += 1

       fut = fut_inspector( fut_record )
       if fut is not None:

          # block...
          fut.wait( 0.1 )
          fut_records.remove( fut_record )
          return fut_record 
   

def future_get_result( fut, timeout ):
   """
   Get the *unpickled* result of a future
   """
   result = fut.get( timeout )
   return pickle.loads( result )


def bitcoin_tx_is_coinbase( tx ):
    """
    Is a transaction a coinbase transaction?
    """
    for inp in tx['vin']:
        if 'coinbase' in inp.keys():
            return True 

    return False


def bitcoin_tx_to_hex( tx ):
     """
     Convert a bitcoin-given transaction into its hex string.
     Does NOT work on coinbase transactions.
     """
     tx_ins = []
     tx_outs = []
     for inp in tx['vin']:
         next_inp = {
            "outpoint": {
               "index": int(inp['vout']),
               "hash": str(inp['txid'])
            }
         }
         if 'sequence' in inp:
             next_inp['sequence'] = int(inp['sequence'])
         else:
             next_inp['sequence'] = UINT_MAX

         if 'scriptSig' in inp:
             next_inp['script'] = str(inp['scriptSig']['hex'])
         else:
             next_inp['script'] = ""

         tx_ins.append(next_inp)
     
     for out in tx['vout']:
         next_out = {
            'value': int(round(Decimal(out['value']) * Decimal(10**8))),
            'script': str(out['scriptPubKey']['hex'])
         }
         tx_outs.append(next_out)

     tx_fields = {
        "locktime": int(tx['locktime']),
        "version": int(tx['version']),
        "ins": tx_ins,
        "outs": tx_outs
     }

     tx_serialized = bitcoin.serialize( tx_fields )
     return str(tx_serialized)


def bitcoin_tx_verify( tx, tx_hash ):
    """
    Confirm that a bitcoin transaction has the given hash.
    """
    tx_serialized = bitcoin_tx_to_hex( tx )
    tx_reversed_bin_hash = bin_double_sha256( binascii.unhexlify(tx_serialized) )
    tx_candidate_hash = binascii.hexlify(tx_reversed_bin_hash[::-1])

    return tx_hash == tx_candidate_hash


def block_header_to_hex( block_data, prev_hash ):
    """
    Calculate the hex form of a block's header, given its getblock information from bitcoind.
    """
    header_info = {
       "version": block_data['version'],
       "prevhash": prev_hash,
       "merkle_root": block_data['merkleroot'],
       "timestamp": block_data['time'],
       "bits": int(block_data['bits'], 16),
       "nonce": block_data['nonce'],
       "hash": block_data['hash']
    }

    return bitcoin.serialize_header( header_info )


def block_header_verify( block_data, prev_hash, block_hash ):
    """
    Verify whether or not bitcoind's block header matches the hash we expect.
    """
    serialized_header = block_header_to_hex( block_data, prev_hash )
    candidate_hash_bin_reversed = bin_double_sha256(binascii.unhexlify(serialized_header))
    candidate_hash = binascii.hexlify( candidate_hash_bin_reversed[::-1] )

    return block_hash == candidate_hash


def block_verify( block_data ):
    """
    Given block data (a dict with 'merkleroot' hex string and 'tx' list of hex strings--i.e.
    a block returned from bitcoind's getblock JSON RPC method), verify that the
    transactions are consistent.

    Return True on success
    Return False if not.
    """
     
    # verify block data txs 
    m = MerkleTree( block_data['tx'] )
    root_hash = str(m.root())

    return root_hash == str(block_data['merkleroot'])


def parse_op_return_payload( magic, op_return_payload ):
    """
    Get the opcode and data from an op_return's payload
    Return op, data on success
    Return None, None on failure
    """
    if magic != op_return_payload[0:1]:
        # not a valid operation
        return (None, None)

    opcode = op_return_payload[0]
    payload = op_return[1:]

    return (opcode, payload)


def pop_length( bin_str ):
    """
    Given a string with a varint, 
    pop the varint.

    Return the value, and the popped string on success
    Return None, None on error
    """
    if len(bin_str) < 2:
        return None, None

    l = 0
    op = ord(bin_str[0])
    bin_str = bin_str[1:]
    if op == opcodes.OP_PUSHDATA1:
        # 1-byte read
        l = ord(bin_str[0])
        bin_str = bin_str[1:]

    elif op == opcodes.OP_PUSHDATA2:
        # 2-byte read
        if len(bin_str) < 2:
            return None, None

        l = ord(bin_str[0]) * (2**8) + ord(bin_str[1])
        bin_str = bin_str[2:]

        if len(bin_str) < l:
            return None, None

    elif op == opcodes.OP_PUSHDATA4:
        # 4-byte read 
        if len(bin_str) < 4:
            return None, None

        l = ord(bin_str[0]) * (2**24) + ord(bin_str[1]) * (2**16) + ord(bin_str[2]) * (2**8) + ord(bin_str[3])
        bin_str = bin_str[4:]
        if len(bin_str) < l:
            return None, None

    else:
        l = op
        if len(bin_str) < l:
            return None, None
    
    return l, bin_str 
    

def pop_string( bin_str ):
    """
    Given a string headed by a varint,
    get $varint bytes.
    Return the string, and the remaining bytes on success.
    Return None, None on error
    """
    l, bin_str = pop_length(bin_str)
    if l is None or bin_str is None:
        return None, None 

    b = bin_str[:l]
    bin_str = bin_str[l+1:]

    return b, bin_str


def parse_multisig_redeem_script( redeem_script_bin ):
    """
    Parse a multisig redeem script.
    Return  M, N, and the list of public keys (as hex strings)
    Return None, None, None on failure.
    """
    failure = (None, None, None)
    m = ord(redeem_script_bin[0])
    if m < opcodes.OP_1 or m > opcodes.OP_16:
        # not multisig 
        return failure

    m -= (opcodes.OP_1 - 1)
    redeem_script_bin = redeem_script_bin[1:]
    
    # get all pubkeys
    pubkeys = []
    for i in xrange(0, m):
        keylen, redeem_script_bin = pop_length( redeem_script_bin )
        pubkeys.append( hexlify(redeem_script_bin[:keylen]) )
        redeem_script_bin = redeem_script_bin[:keylen]

    # get n
    n = ord(redeem_script_bin[0])
    redeem_script_bin = redeem_script_bin[1:]
    if n < opcodes.OP_1 or n > opcodes.OP_16:
        # not multisig
        return failure

    n -= (opcodes.OP_1 - 1)
    if n < m:
        # invalid 
        return failure

    # last byte should be OP_CHECKMULTISIG 
    if len(redeem_script_bin) != 1:
        return failure

    if ord(redeem_script_bin[0]) != opcodes.OP_CHECKMULTISIG:
        return failure

    return m, n, pubkeys
    

def parse_multisig_info( input_hex ):
    """
    Given an asm string from a scriptsig,
    try to parse it as a multisig input.
    Return the (m, n, list of signatures on success (as hex strings), and the list of public keys in the redeem script)
    Return None, None, None, None if not a multisig input.
    """
    sigs = []
    input_bin = unhexlify(input_hex)
    failure = (None, None, None, None)

    # first byte must be OP_0
    if ord(input_bin[0]) != opcodes.OP_0:
        return failure

    input_bin = input_bin[1:]
    strings = []
    while len(input_bin) > 0:
        sig, input_bin = pop_string(input_bin)
        if sig is None:
            return failure

        strings.append(sig)

    redeem_script = strings.pop()

    # extract keys 
    m, n, public_keys = parse_multisig_redeem_script( redeem_script )
    if m is None or n is None or public_keys is None:
        return failure

    # must be m signatures
    if len(strings) != m:
        return failure
        
    return m, n, strings, public_keys


def get_public_keys_and_signatures( tx_input ):
    """
    Given a bitcoin-given vin, find the public keys.
    Returns a (list of signatures, list of public keys)
    Returns None,None on error
    """

    failure = (None, None) 
    input_scriptsig = tx_input.get('scriptSig', None )
    if input_scriptsig is None:
        # no scriptsig, no public keys
        return failure
        
    input_hex = input_scriptsig.get("hex")
    input_asm = input_scriptsig.get("asm")
    if input_hex is None:
        return failure

    if input_asm is None:
        return failure

    # is this a p2pkh input?
    if input_asm.split(" ") == 2:
        signature_hex, pubkey_hex = input_asm.split(" ")
        try:
            pubkey = ECPublicKey(str(pubkey_hex))
        except Exception, e:
            continue

        return [signature_hex], [pubkey_hex]

    # is this a p2sh multisig input?
    m, n, signatures, public_keys = parse_multisig_info( input_hex )
    if public_keys is not None:
        return (signatures, public_keys)

    return failure



def get_virtualchain_transactions( workpool, bitcoind_opts, magic, blocks_ids, first_block_hash=None ):
   """
   Obtain the set of transactions over a range of blocks that have an OP_RETURN with nulldata.
   Each returned transaction record will contain:
   * vin (list of inputs from bitcoind)
   * vout (list of outputs from bitcoind)
   * txid (transaction ID, as a hex string)
   * txindex (transaction index in the block)
   * senders (a list of {"script_pubkey":, "amount":, "addresses":} dicts in order by input; the "script_pubkey" field is the hex-encoded op script).
   * fee (total amount sent)
   * nulldata (input data to the transaction's script; encodes virtual chain operations)
   
   Farm out the requisite RPCs to a workpool of processes, each 
   of which have their own bitcoind RPC client.
   
   Returns [(block_number, [txs])], where each tx contains the above.
   """
   
   nulldata_tx_map = {}    # {block_number: {"tx": [tx]}}
   nulldata_txs = []
   
   # break work up into slices of blocks, so we don't run out of memory 
   slice_len = multiprocess_batch_size( bitcoind_opts )
   slice_count = 0
   last_block_hash = first_block_hash
   
   while slice_count * slice_len < len(blocks_ids):
      
      block_hashes = {}  # map block ID to block hash 
      block_datas = {}    # map block hashes to block data
      block_hash_futures = []
      block_data_futures = []
      tx_futures = []
      sender_tx_futures = []
      
      block_slice = blocks_ids[ (slice_count * slice_len) : min((slice_count+1) * slice_len, len(blocks_ids)) ]
      if len(block_slice) == 0:
         log.debug("Zero-length block slice")
         break
      
      # get all block hashes 
      for block_number in block_slice:
         
         block_times[block_number] = time.time() 
         
         block_hash_fut = getblockhash_async( workpool, bitcoind_opts, block_number )
         block_hash_futures.append( (block_number, block_hash_fut) ) 
   
      # coalesce all block hashes
      for i in xrange(0, len(block_hash_futures)):
         
         block_number, block_hash_fut = future_next( block_hash_futures, lambda f: f[1] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_hash = future_get_result( block_hash_fut, 10000000000000000L )
         block_hashes[block_number] = block_hash
       
         # start getting each block's data
         if block_hash is not None:
             block_data_fut = getblock_async( workpool, bitcoind_opts, block_hash )
             block_data_futures.append( (block_number, block_data_fut) )

         else:
             raise Exception("BUG: Block %s: no block hash" % block_number)
     
      # coalesce block data
      for i in xrange(0, len(block_data_futures)):
         
         block_number, block_data_fut = future_next( block_data_futures, lambda f: f[1] )
         block_hash_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_data = future_get_result( block_data_fut, 1000000000000000L )
         
         if 'tx' not in block_data:
             raise Exception("BUG: No tx data in block %s" % block_number)
         
         block_datas[ block_hashes[block_number] ] = block_data
     

      # verify blockchain headers
      for i in xrange(0, len(block_slice)):
          block_id = block_slice[i]
          block_hash = block_hashes[block_id]

          prev_block_hash = None
          if i > 0:
              prev_block_id = block_slice[i-1]
              prev_block_hash = block_hashes[prev_block_id]

          elif last_block_hash is not None:
              prev_block_hash = last_block_hash 

          else:
              continue

          if not block_header_verify( block_datas[block_hash], prev_block_hash, block_hash ):
              serialized_header = block_header_to_hex( block_datas[block_hash], prev_block_hash )
              candidate_hash_reversed = bin_double_sha256(binascii.unhexlify(serialized_header))
              candidate_hash = binascii.hexlify(candidate_hash_reversed[::-1])
              raise Exception("Hash mismatch on block %s: got invalid block hash (expected %s, got %s)" % (block_id, block_hash, candidate_hash))

      last_block_hash = block_hashes[ block_slice[-1] ]

      for block_number in block_slice:
         
         block_hash = block_hashes[block_number]
         block_data = block_datas[block_hash]
         
         # verify block data txs
         rc = block_verify( block_data )
         if not rc:
             raise Exception("Hash mismatch on block %s: got invalid Merkle root (expected %s)" % (block_hash, block_data['merkleroot']))

         # go get each transaction
         tx_hashes = block_data['tx']
         
         log.debug("Get %s transactions from block %s" % (len(tx_hashes), block_hash))
         
         # can get transactions asynchronously with a workpool (but preserve tx order!)
         if len(tx_hashes) > 0:
           
            for j in xrange(0, len(tx_hashes)):
               
               tx_hash = tx_hashes[j]
               tx_fut = getrawtransaction_async( workpool, bitcoind_opts, tx_hash, 1 )
               tx_futures.append( (block_number, j, tx_fut) )
            
         else:
            
            raise Exception("BUG: Zero-transaction block %s" % block_number)
           
      # coalesce raw transaction queries...
      for i in xrange(0, len(tx_futures)):
         
         block_number, tx_index, tx_fut = future_next( tx_futures, lambda f: f[2] )
         block_data_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         tx = future_get_result( tx_fut, 1000000000000000L )
         
         #if len(tx['vin']) > 0 and 'coinbase' not in tx['vin'][0].keys():
         if not bitcoin_tx_is_coinbase( tx ):

             # verify non-coinbase transaction 
             tx_hash = tx['txid']
             if not tx_verify( tx, tx_hash ):
                 raise Exception("Transaction hash mismatch in %s (index %s) in block %s" % (tx['txid'], tx_index, block_number))

         if tx and has_nulldata(tx):
            
            # go get input transactions for this transaction (since it's the one with nulldata, i.e., a virtual chain operation),
            # but tag each future with the hash of the current tx, so we can reassemble the in-flight inputs back into it. 
            sender_futs_and_output_idxs = process_nulldata_tx_async( workpool, bitcoind_opts, tx )
            sender_tx_futures.append( (block_number, tx_index, tx, sender_futs_and_output_idxs) )
     

      # coalesce queries on the inputs to each nulldata transaction from this block...
      for (block_number, tx_index, tx, sender_futs_and_output_idxs) in sender_tx_futures:
         
         if ('vin' not in tx) or ('vout' not in tx) or ('txid' not in tx):
            continue 
        
         inputs = tx['vin']
         outputs = tx['vout']
         
         # total_in = 0   # total input paid
         senders = []
         ordered_senders = []

         if bitcoin_tx_is_coinbase( tx ):
             # skip coinbase 
             continue
         
         # gather this tx's inputs' outputs (so we know who sent which input)
         for i in xrange(0, len(sender_futs_and_output_idxs)):
            
            input_idx, input_tx_fut, tx_output_index = future_next( sender_futs_and_output_idxs, lambda f: f[1] )
            
            # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
            input_tx = future_get_result( input_tx_fut, 1000000000000000L )
            input_tx_hash = input_tx['txid']

            # verify (but skip coinbase) 
            if not bitcoin_tx_is_coinbase( input_tx ):
                try:
                    if not tx_verify( input_tx, input_tx_hash ):
                        raise Exception("Input transaction hash mismatch %s from tx %s (index %s)" % (input_tx['txid'], tx['txid'], tx_output_index))
                except:
                    pp = pprint.PrettyPrinter()
                    pp.pprint(input_tx)
                    raise

            sender = get_output_from_tx( input_tx, tx_output_index )
            if sender is None:
                continue

            amount_in = sender.amount()
            # total_in += amount_in 
            
            # preserve sender order...
            ordered_senders.append( (input_idx, sender) )
         
         # sort on input_idx, so the list of senders matches the given transaction's list of inputs
         # that is, senders and tx['vin'] are in one-to-one correspondence by index.
         ordered_senders.sort()
         senders = [sender for (_, sender) in ordered_senders]

         # sanity check...
         if len(senders) != len(inputs):
             raise Exception("Sender/inputs mismatch: %s != %s\n" % (len(senders), len(inputs)))
         
         # merge senders into vin 
         for i in xrange(0, len(inputs)):
             tx['vin'][i]['_virtualchain_sender'] = senders[i]
         
         # extract public keys and signatures 
         for i in xrange(0, len(inputs)):
             tx['vin'][i]['_virtualchain_public_keys'] = get_public_keys( inputs[i] )
             tx['vin'][i]['_virtualchain_signatures'] = get_signatures( inputs[i] )

         # track the order of nulldata-containing transactions in this block
         if not nulldata_tx_map.has_key( block_number ):
            nulldata_tx_map[ block_number ] = [(tx_index, tx)]
            
         else:
            nulldata_tx_map[ block_number ].append( (tx_index, tx) )
            
      # next slice
      slice_count += 1
 
   # convert to virtualchain format
   vtxs = []
   for block_number in block_ids:
       if block_number in nulldata_tx_map.keys():
           # payload-bearing transactions for this block...
           tx_list = nulldata_tx_map[ block_number ]  # [(tx_index, tx)]
           tx_list.sort()
           
           # preserve index 
           for (tx_index, tx) in tx_list:
               tx['txindex'] = tx_index

            txs = [tx for (_, tx) in tx_list]

        # build virtual transactions
        for tx in txs:
            vtx_inputs = []
            vtx_outputs = []
            payload = None
            valid = True

            for inp in tx['vin']:
                if inp.has_key('scriptSig'):
                    # pass along 
                    public_keys, signatures = get_public_keys_and_signatures( inp )
                    if public_keys is None or signatures is None:
                        log.error("Unrecognized scriptSig in transaction %s: %s" % (tx['txid'], inp['scriptSig'].get('hex')))
                        valid = False
                        break

                    vtx_in = VirtualInput( inp['scriptSig']['hex'], public_keys, signatures, scriptSig=inp['scriptSig'], sender=inp['_virtualchain_sender'], txid=inp['txid'] )
                    vtx_inputs.append( vtx_in )

            if not valid:
                continue

            for outp in tx['vout']:
                amount = int(outp['value'] * (10**8))
                if outp.has_key('scriptPubKey'):
                    if outp['scriptPubKey']['type'] == 'nulldata':
                        # pass along data output
                        assert payload is None, "More than one OP_RETURN transaction in %s" % tx['txid']
                        hex_script = outp['scriptPubKey']['hex'].decode('hex')
                        payload = hex_script[4:]
                        op, data = parse_op_return_payload( magic, payload )
                        vtx_out = VirtualDataOutput( outp['scriptPubKey']['hex'], op, data, amount=amount, script_pubkey=outp['scriptPubKey'] ) 
                        vtx_outputs.append( vtx_out )

                    else:
                        # pass along value output 
                        vtx_out = VirtualPaymentOutput( outp['scriptPubKey']['hex'], amount, outp['scriptPubKey'].get('addresses', []), script_pubkey=outp['scriptPubKey'] )
                        vtx_outputs.append( vtx_out )

            assert payload is not None, "No OP_RETURN transaction in %s" % tx['txid']
            vtx = VirtualTransaction( block_number, tx['txid'], tx['txindex'], vtx_inputs, vtx_outputs )
            vtxs.append( vtx )

   return vtxs


def txid_to_block_data(txid, bitcoind_proxy, blockchain_headers_path):
    """
    Given a txid, get its block's data.

    Use SPV to verify the information we receive from the (untrusted)
    bitcoind host.

    @bitcoind_proxy must be a BitcoindConnection

    Return the (block hash, block data, txdata) on success
    Return (None, None, None) on error
    """

    timeout = 1.0
    while True:
        try:
            untrusted_tx_data = bitcoind_proxy.getrawtransaction(txid, 1)
            untrusted_block_hash = untrusted_tx_data['blockhash']
            untrusted_block_data = bitcoind_proxy.getblock(untrusted_block_hash)
            break
        except Exception, e:
            log.exception(e)
            log.error("Unable to obtain block data; retrying...")
            time.sleep(timeout)
            timeout = timeout * 2 + random.random() * timeout

    SPVClient.init(blockchain_headers_path)

    # first, can we trust this block? is it in the SPV headers?
    untrusted_block_header_hex = block_header_to_hex(untrusted_block_data, untrusted_block_data['previousblockhash'])
    block_id = SPVClient.block_header_index(blockchain_headers_path, (untrusted_block_header_hex + "00").decode('hex'))
    if block_id < 0:
        # bad header
        log.error("Block header '%s' is not in the SPV headers" % untrusted_block_header_hex)
        return (None, None, None)

    # block header is trusted.  Is the transaction data consistent with it?
    if not block_verify(untrusted_block_data):
        log.error("Block transaction IDs are not consistent with the trusted header's Merkle root")
        return (None, None, None)

    # verify block hash
    if not block_header_verify(untrusted_block_data, untrusted_block_data['previousblockhash'], untrusted_block_hash):
        log.error("Block hash is not consistent with block header")
        return (None, None, None)

    # we trust the block hash, block data, and txids
    block_hash = untrusted_block_hash
    block_data = untrusted_block_data
    tx_data = untrusted_tx_data

    return (block_hash, block_data, tx_data)



def txid_to_serial_number(txid, bitcoind_proxy):
    """
    Given a transaction ID, convert it into a serial number
    (defined as $block_id-$tx_index).

    Use SPV to verify the information we receive from the (untrusted)
    bitcoind host.

    @bitcoind_proxy must be a BitcoindConnection

    Return the serial number on success
    Return None on error
    """

    block_hash, block_data, _ = txid_to_block_data(txid, bitcoind_proxy )
    if block_hash is None or block_data is None:
        return None

    # What's the tx index?
    try:
        tx_index = block_data['tx'].index(txid)
    except:
        # not actually present
        log.error("Transaction %s is not present in block %s (%s)" % (txid, block_id, block_hash))

    return "%s-%s" % (block_id, tx_index)



def serial_number_to_tx(serial_number, bitcoind_proxy, blockchain_headers_path ):
    """
    Convert a serial number into its transaction in the blockchain.
    Use an untrusted bitcoind connection to get the list of transactions,
    and use trusted SPV headers to ensure that the transaction obtained is on the main chain.
    @bitcoind_proxy must be a BitcoindConnection 

    Return the SPV-verified transaction object (as a dict) on success
    Return None on error
    """

    parts = serial_number.split("-")
    block_id = int(parts[0])
    tx_index = int(parts[1])

    timeout = 1.0
    while True:
        try:
            block_hash = bitcoind_proxy.getblockhash(block_id)
            block_data = bitcoind_proxy.getblock(block_hash)
            break
        except Exception, e:
            log.error("Unable to obtain block data; retrying...")
            time.sleep(timeout)
            timeout = timeout * 2 + random.random() * timeout

    SPVClient.init(blockchain_headers_path)

    rc = SPVClient.sync_header_chain(blockchain_headers_path, bitcoind_proxy.opts['bitcoind_server'], block_id)
    if not rc:
        log.error("Failed to synchronize SPV header chain up to %s" % block_id)
        return None

    # verify block header
    rc = SPVClient.block_header_verify(blockchain_headers_path, block_id, block_hash, block_data)
    if not rc:
        log.error("Failed to verify block header for %s against SPV headers" % block_id)
        return None

    # verify block txs
    rc = SPVClient.block_verify(block_data, block_data['tx'])
    if not rc:
        log.error("Failed to verify block transaction IDs for %s against SPV headers" % block_id)
        return None

    # sanity check
    if tx_index >= len(block_data['tx']):
        log.error("Serial number %s references non-existant transaction %s (out of %s txs)" % (serial_number, tx_index, len(block_data['tx'])))
        return None

    # obtain transaction
    txid = block_data['tx'][tx_index]
    tx = bitcoind_proxy.getrawtransaction(txid, 1)

    # verify tx
    rc = SPVClient.tx_verify(block_data['tx'], tx)
    if not rc:
        log.error("Failed to verify block transaction %s against SPV headers" % txid)
        return None

    # verify tx index
    if tx_index != SPVClient.tx_index(block_data['tx'], tx):
        log.error("TX index mismatch: serial number identifies transaction number %s (%s), but got transaction %s" % \
                (tx_index, block_data['tx'][tx_index], block_data['tx'][ SPVClient.tx_index(block_data['tx'], tx) ]))
        return None

    # success!
    return tx


def calculate_change_amount(inputs, send_amount, fee):
    # calculate the total amount  coming into the transaction from the inputs
    total_amount_in = sum([input['value'] for input in inputs])
    # change = whatever is left over from the amount sent & the transaction fee
    change_amount = total_amount_in - send_amount - fee
    # check to ensure the change amount is a non-negative value and return it
    if change_amount < 0:
        raise Exception('Not enough inputs for transaction.')

    return change_amount


def make_pay_to_address_outputs(to_address, send_amount, inputs, change_address,
                                fee=STANDARD_FEE):
    """ Builds the outputs for a "pay to address" transaction.
    """
    return [
        # main output
        { "script_hex": make_pay_to_address_script(to_address), "value": send_amount },
        # change output
        { "script_hex": make_pay_to_address_script(change_address),
          "value": calculate_change_amount(inputs, send_amount, fee)
        }
    ]

def make_op_return_outputs(data, inputs, change_address, fee=OP_RETURN_FEE,
                           send_amount=0, format='bin'):
    """ Builds the outputs for an OP_RETURN transaction.
    """
    return [
        # main output
        { "script_hex": make_op_return_script(data, format=format), "value": send_amount },
        # change output
        { "script_hex": make_pay_to_address_script(change_address),
          "value": calculate_change_amount(inputs, send_amount, fee)
        }
    ]


def bitcoin_tx_deserialize( tx_hex ):
    """
    Given a serialized transaction, return its inputs, outputs, locktime, and version
    Each input will have:
    * transaction_hash: string 
    * output_index: int 
    * [optional] sequence: int 
    * [optional] script_sig: string
    
    Each output will have:
    * value: int 
    * script_hex: string

    Return (inputs, outputs, locktime, version)
    """
    
    tx = bitcoin.deserialize( tx_hex )
    inputs = tx["ins"]
    outputs = tx["outs"]
    
    ret_inputs = []
    ret_outputs = []
    
    for inp in inputs:
        ret_inp = {
            "transaction_hash": inp["outpoint"]["hash"],
            "output_index": int(inp["outpoint"]["index"]),
        }
        
        if "sequence" in inp:
            ret_inp["sequence"] = int(inp["sequence"])
            
        if "script" in inp:
            ret_inp["script_sig"] = inp["script"]
            
        ret_inputs.append( ret_inp )
        
    for out in outputs:
        ret_out = {
            "value": out["value"],
            "script_hex": out["script"]
        }
        
        ret_outputs.append( ret_out )
        
    return ret_inputs, ret_outputs, tx["locktime"], tx["version"]


def bitcoin_tx_serialize( inputs, outputs, locktime=0, version=1 ):
    """
    Given (possibly signed) inputs and outputs, convert them 
    into a hex string suitable for broadcasting.
    Each input must have:
    * transaction_hash: string 
    * output_index: int 
    * [optional] sequence: int 
    * [optional] script_sig: str 
    
    Each output must have:
    * value: int 
    * script_hex: string
    """
    
    tmp_inputs = []
    tmp_outputs = []
    
    # convert to a format bitcoin understands
    for inp in inputs:
        tmp_inp = {
            "outpoint": {
                "index": inp["output_index"],
                "hash": inp["transaction_hash"]
            }
        }
        if "sequence" in inp:
            tmp_inp["sequence"] = inp["sequence"]
        else:
            tmp_inp["sequence"] = 2**32 - 1     # max uint32
            
        if "script_sig" in inp:
            tmp_inp["script"] = inp["script_sig"]
        else:
            tmp_inp["script"] = ""
            
        tmp_inputs.append( tmp_inp )
        
    for out in outputs:
        tmp_out = {
            "value": out["value"],
            "script": out["script_hex"]
        }
        
        tmp_outputs.append( tmp_out )
        
    txobj = {
        "locktime": locktime,
        "version": version,
        "ins": tmp_inputs,
        "outs": tmp_outputs
    }
    
    return bitcoin.serialize( txobj )
    

def bitcoin_tx_serialize_and_sign_multi( inputs, outputs, private_keys ):
    """
    Given a list of inputs, outputs, private keys, and optionally a partially-signed transaction:
    * make a transaction out of the inputs and outputs 
    * sign input[i] with private_key[i]
    
    Return the signed tx on success
    """
    
    if len(inputs) != len(private_keys):
        raise Exception("Must have the same number of private keys as inputs")
    
    private_key_objs = []
    for pk in private_keys:
        if isinstance( pk, ECPrivateKey ):
            private_key_objs.append( pk )
        else:
            private_key_objs.append( ECPrivateKey( pk ) )
            
    # make the transaction 
    unsigned_tx = bitcoin_tx_serialize( inputs, outputs )
    
    # sign with the appropriate private keys 
    for i in xrange(0, len(inputs)):
        signed_tx = bitcoin.sign( unsigned_tx, i, private_key_objs[i].to_hex() )
        unsigned_tx = signed_tx 
        
    return unsigned_tx 


def bitcoin_tx_serialize_and_sign( inputs, outputs, private_key ):
    """
    Create a serialized transaction and sign each input with the same private key.
    Useful for making a tx that is sent from one key.
    """
    return bitcoin_tx_serialize_and_sign_multi( inputs, outputs, [private_key] * len(inputs) )


def bitcoin_tx_extend( partial_tx_hex, new_inputs, new_outputs ):
    """
    Given an unsigned serialized transaction, add more inputs and outputs to it.
    """
    
    # recover tx
    inputs, outputs, locktime, version = bitcoin_tx_deserialize( partial_tx_hex )
    
    # new tx
    new_unsigned_tx = bitcoin_tx_serialize( inputs + new_inputs, outputs + new_outputs, locktime, version )
        
    return new_unsigned_tx

    
def bitcoin_tx_output_is_op_return( output ):
    """
    Is an output's script an OP_RETURN script?
    """
    return int( output["script_hex"][0:2], 16 ) == OP_RETURN
    

def bitcoin_tx_sign_output( unsigned_tx, output_index, privkey_hex ):
    """
    Sign an output in a transaction
    """
    return bitcoin.sign( unsigned_tx, output_index, privkey_hex )


# driver method 
def tx_parse( tx_str ):
    """
    Parse a transaction
    """
    inputs, outputs, locktime, version = bitcoin_tx_deserialize( tx_str )
    return {
        "blockchain": "bitcoin",
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
        "version": version
    }


# driver method 
def tx_serialize( vinputs, voutputs, **fields ):
    """
    Serialize a transaction, from its virtual inputs and virtual outputs
    """
    locktime = 0
    version = 1
    if "locktime" in fields:
        locktime = fields['locktime']
    if 'version' in fields:
        version = fields['version']

    # convert to bitcoin outputs 
    outputs = []

    for vout in voutputs:
        if vout.type() == "payment":
            outputs
    
    return bitcoin_tx_serialize( tx_dict['inputs'], tx_dict['outputs'], tx_dict['locktime'], tx_dict['version'] )


# driver method 
def tx_serialize_sign( inputs, outputs, private_key, **fields ):
    """
    Serialize and sign a transaction, from its virtual inputs and virtual outputs
    """ 
    locktime = 0
    version = 1
    if "locktime" in fields:
        locktime = fields['locktime']
    if 'version' in fields:
        version = fields['version']

    return bitcoin_tx_serialize_and_sign( tx_dict['inputs'], tx_dict['outputs'], private_key )
