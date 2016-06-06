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

from keylib import b58check_decode, ECPublicKey
from binascii import hexlify, unhexlify
from utilitybelt import is_hex
from opcodes import *

MAX_BYTES_AFTER_OP_RETURN = 80

def count_bytes(hex_s):
    assert is_hex(hex_s)
    return len(hex_s)/2

def script_to_hex(script):
    """ Parse the string representation of a script and return the hex version.
        Example: "OP_DUP OP_HASH160 c629...a6db OP_EQUALVERIFY OP_CHECKSIG"
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
        if part[0:3] == 'OP_':
            try:
                hex_script += '%0.2x' % eval(part)
            except:
                raise Exception('Invalid opcode: %s' % part)
        elif isinstance(part, (int)):
            hex_script += '%0.2x' % part
        elif is_hex(part):
            hex_script += '%0.2x' % count_bytes(part) + part
        else:
            raise Exception('Invalid script - only opcodes and hex characters allowed.')
    return hex_script

def make_pay_to_address_script(address):
    """ Takes in an address and returns the script 
    """
    hash160 = hexlify(b58check_decode(address))
    script_string = 'OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG' % hash160
    return script_to_hex(script_string)


def make_op_return_script(data, format='bin'):
    """ Takes in raw ascii data to be embedded and returns a script.
    """
    if format == 'hex':
        assert(is_hex(data))
        hex_data = data
    elif format == 'bin':
        hex_data = hexlify(data)
    else:
        raise Exception("Format must be either 'hex' or 'bin'")

    num_bytes = count_bytes(hex_data)
    if num_bytes > MAX_BYTES_AFTER_OP_RETURN:
        raise Exception('Data is %i bytes - must not exceed 40.' % num_bytes)

    script_string = 'OP_RETURN %s' % hex_data
    return script_to_hex(script_string)


# generate a pay-to-pubkeyhash script from a public key.
def get_script_pubkey( public_key ):
   
   hash160 = ECPublicKey(public_key).hash160()
   script_pubkey = script_to_hex( 'OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG' % hash160)
   return  script_pubkey


def bin_hash160_to_address(bin_hash160, version_byte=0):
    return b58check_encode(bin_hash160, version_byte=version_byte)


def hex_hash160_to_address(hash160, version_byte=0):
    return bin_hash160_to_address(
        unhexlify(hash160), version_byte=version_byte)


def script_hex_to_address(script, version_byte=0):
    # TODO: only works on pay-to-pubkey-hash scripts
    # FIXME
    if script[0:6] == '76a914' and script[-4:] == '88ac':
        bin_hash160 = unhexlify(script[6:-4])
        return bin_hash160_to_address(bin_hash160, version_byte=version_byte)
    return None


def address_to_bin_hash160(address):
    return b58check_decode(address)


def address_to_hex_hash160(address):
    return hexlify(address_to_bin_hash160(address))


