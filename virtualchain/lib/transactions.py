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

class VirtualInput(object):
    """
    Virtualchain transaction input
    """
    def __init__(self, public_keys, sigs, **fields):
        """
        * public_keys is the list of public keys
        * sigs is the list of signatures
        """
        self._sigs = sigs
        self._public_keys = public_keys
        self._fields = fields

    @classmethod
    def from_string(cls, s):
        # load from JSON 
        obj = json.loads(s)
        return VirtualInput( obj['sig'], **obj['special'] )

    def public_keys(self):
        return self._public_keys

    def sigs(self):
        return self._sigs

    def special( self, name ):
        return self._fields.get(name, None)

    def __repr__(self):
        obj = {
            "public_keys": self.public_keys()
            "sigs": self.sigs(),
            "special": self._fields
        }
        return json.dumps(obj)


class VirtualOutput(object):
    """
    Virtual transaction output (each virtual transaction has at least one)
    """
    def __init__(self, sender_id, amount, addresses, **fields):
        """
        * sender_id is an opaque string that identifies the sender (e.g. a script_pubkey in Bitcoin)
        * amount is the number of tokens the input can move
        * addresses is a list of blockchain-specific recipient identifiers
        """

        self._amount = amount
        self._sender_id = sender_id
        self._fields = fields
        self._addresses = addresses

    @classmethod
    def from_string(cls, s):
        # load from JSON
        obj = json.loads(s)
        assert obj['type'] == "unknown"
        return VirtualOutput( obj['sender_id'], obj['amount'], obj['addresses'], **obj['fields'])
    
    def type(self):
        return "unknown"

    def amount(self):
        return self._value

    def sender_id(self):
        return self._sender_id

    def addresses(self):
        return self._addresse

    def special( self, name ):
        return self._fields.get(name, None)

    def __repr__(self):
        # JSON representation
        obj = {
            "amount": self.amount(),
            "sender_id": self.sender_id(),
            "type": self.type(),
            "addresses": self.addresses(),
            "special": self._fields
        }
        return json.dumps(obj)


class VirtualDataOutput(VirtualTransaction):
    def __init__(self, sender_id, opcode, data, amount=0, **fields):
        super(VirtualDataOutput, self).__init__(sender_id, amount, [], **fields)
        self._data = data
        self._opcode = opcode

    @classmethod 
    def from_string(cls, s):
        obj = json.loads(s)
        assert obj['type'] == "data"
        return VirtualDataOutput( obj['sender_id'], obj['opcode'], obj['payload'], amount=obj['amount'], **obj['special'])

    def type(self):
        return "data"

    def payload(self):
        return self._data

    def opcode(self):
        return self._opcode

    def __repr__(self):
        s = super(VirtualDataOutput, self).__repr__()
        obj = json.loads(s)
        obj['type'] = self.type()
        obj['payload'] = self.payload()
        obj['opcode'] = self.opcode()
        return json.dumps(obj)


class VirtualPaymentOutput(VirtualTransaction):
    
    def type(self):
        return "payment"

    @classmethod
    def from_string(cls, s):
        obj = json.loads(s)
        assert ob['type'] == 'payment'
        return VirtualPaymentOutput( obj['sender_id'], obj['amount'], obj['addresses'], **obj['fields'])


def VirtualTransaction(object):
    """
    Virtual transaction
    """
    def __init__(self, block_id, txid, txindex, inputs, outputs ):
        """
        * block_id is the numeric ID (height) of the block
        * txid is the blockchain-specific transaction identifier
        * txindex is the offset into the block where the transaction occurs
        * inputs is a list of VirtualInput objects
        * outputs is a list of VirtualOuput objects
        * fee is the amount of currency units it cost to produce this transaction
        * payload is a string that encodes a virtualchain transaction
        """
        self._block_id = block_id
        self._txid = txid
        self._txindex = txindex
        self._inputs = inputs
        self._outputs = outputs
        self._opcode = None
        self._payload = None

        try:
            self._find_payload()
        except:
            raise ValueError("Expected exactly one data output")

    @classmethod
    def from_string(self, s):
        obj = json.loads(s)
        return VirtualTransaction( obj['block_id'], obj['txid'], obj['txindex'], obj['inputs'], obj['outputs'] )

    def block_id(self):
        return self._block_id

    def txid(self):
        return self._txid

    def txindex(self):
        return self._txindex

    def inputs(self):
        return self._inputs

    def outputs(self):
        return self._outputs

    def fee(self):
        all_in = sum( [inp.amount() for inp in self._inputs] )
        all_out = sum( [outp.amount() for outp in self._outputs] )
        return all_in - all_out


    def _find_payload(self):
        if self._payload is None or self._opcode is None:
            # find opcode and payload 
            o = None
            p = None
            for outp in self._outputs:
                if outp.type() == "data":
                    assert o is None
                    assert p is None
                    o = outp.opcode()
                    p = outp.payload()

            assert o is not None and p is not None
            self._payload = p
            self._opcode = o

    def payload(self):
        return self._payload

    def opcode(self):
        return self._opcode

    def __repr__(self):
        obj = {
            "block_id": self.block_id(),
            "txid": self.txid(),
            "txindex": self.txindex(),
            "inputs": [str(inp) for inp in self.inputs()],
            "outputs": [str(outp) for outp in self.outputs()],
        }
        return json.dumps(obj)
