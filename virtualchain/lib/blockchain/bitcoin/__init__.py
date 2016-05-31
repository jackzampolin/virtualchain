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

# these are methods that each blockchain module must implement...
from session import get_bitcoind_config as get_blockchain_config
from session import connect_bitcoind_impl as connect_blockchain
from transactions import getblockcount as get_blockchain_height
from transactions import get_nulldata_txs_in_blocks as get_virtualchain_transactions
from session import AVERAGE_BLOCKS_PER_HOUR

# for SNV
from transactions import txid_to_block_data as snv_txid_to_block_data
from transactions import txid_to_serial_number as snv_txid_to_serial_number
from transactions import serial_number_to_tx as snv_serial_number_to_tx
from transactions import parse_tx_op_return as snv_tx_parse
