#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org
    
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

# TODO: stub methods for now 
def txid_to_block_data(txid, ethereum_proxy, blockchain_headers_path):
    raise NotImplementedError()

def txid_to_serial_number(txid, bitcoind_proxy):
    raise NotImplementedError()

def serial_number_to_tx(serial_number, bitcoind_proxy, blockchain_headers_path ):
    raise NotImplementedError()

def getblockcount( ethereum_or_opts ):
    raise NotImplementedError()

def parse_ethereum_virtualchain_tx(tx):
    raise NotImplementedError()

def get_ethereum_virtualchain_transactions( workpool, ethereum_opts, block_ids, first_block_hash=None ):
    raise NotImplementedError()

def tx_parse( tx_str ):
    raise NotImplementedError()

def tx_serialize( inputs, outputs, **fields ):
    raise NotImplementedError()

def tx_serialize_sign( inputs, outputs, private_key, **fields ):
    raise NotImplementedError()
