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


import os
import argparse
import logging
import importlib
import types
import imp
from ConfigParser import SafeConfigParser

DEBUG = True
TESTSET = False
IMPL = None             # class, package, or instance that implements the virtual chain state

""" virtualchain daemon configs
"""

RPC_TIMEOUT = 5  # seconds

MULTIPROCESS_RPC_RETRY = 10

REINDEX_FREQUENCY = 10  # in seconds

AVERAGE_MINUTES_PER_BLOCK = 10
DAYS_PER_YEAR = 365.2424
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
SECONDS_PER_MINUTE = 60
MINUTES_PER_YEAR = DAYS_PER_YEAR*HOURS_PER_DAY*MINUTES_PER_HOUR
SECONDS_PER_YEAR = int(round(MINUTES_PER_YEAR*SECONDS_PER_MINUTE))
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR

# attributes we'll need
BLOCKCHAIN_MOD_PROTOTYPE = {
    "get_blockchain_config": [types.FunctionType, callable],
    "connect_blockchain": [types.FunctionType, callable],
    "get_blockchain_height": [types.FunctionType, callable],
    "get_virtualchain_transactions": [types.FunctionType, callable],
    "snv_txid_to_block_data": [types.FunctionType, callable],
    "snv_serial_number_to_tx_data": [types.FunctionType, callable],
    "snv_tx_parse": [types.FunctionType, callable],
    "AVERAGE_BLOCKS_PER_HOUR": [int,long,float]
}

BLOCKCHAIN_CONFIG_REQUIRED_VALUES = [
    "blockchain",
    "blockchain_server",
    "blockchain_port"
]

NUM_CONFIRMATIONS = {
    "bitcoin": 6,
    "ethereum": 240
}


def blockchain_confirmations( blockchain_name ):
    """
    Determine how many blocks to wait before accepting new records
    """
    blockchain_mod = import_blockchain( blockchain_name )
    return blockchain_mod.AVERAGE_BLOCKS_PER_HOUR
    

def get_logger(name=None):
    """
    Get virtualchain's logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + ') %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log

log = get_logger("virtualchain")

def get_impl(impl):
    """
    Get the implementation--either
    the given one (if not None), or
    the globally-set one (if not None).
    Raise exception if both are None.
    """
    global IMPL
    if impl is not None:
        return impl

    elif IMPL is not None:
        return IMPL

    else:
        raise Exception("No virtualchain implementation set")


def get_first_block_id(impl=None):
    """
    facade to implementation's first block
    """
    impl = get_impl(impl)
    return impl.get_first_block_id()


def get_working_dir(impl=None):
    """
    Get the absolute path to the working directory.
    """

    if os.environ.has_key("VIRTUALCHAIN_WORKING_DIR"):
        return os.environ["VIRTUALCHAIN_WORKING_DIR"]

    impl = get_impl(impl)

    from os.path import expanduser
    home = expanduser("~")

    working_dir = None
    if hasattr(impl, "working_dir") and impl.working_dir is not None:
        working_dir = impl.working_dir

    else:
        working_dir = os.path.join(home, "." + impl.get_virtual_chain_name(testset=TESTSET))

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    return working_dir


def get_config_filename(impl=None):
    """
    Get the absolute path to the config file.
    """
    impl = get_impl(impl)

    working_dir = get_working_dir(impl=impl)
    config_filename = impl.get_virtual_chain_name(testset=TESTSET) + ".ini"

    return os.path.join(working_dir, config_filename)


def get_db_filename(impl=None):
    """
    Get the absolute path to the last-block file.
    """
    impl = get_impl(impl)

    working_dir = get_working_dir(impl=impl)
    lastblock_filename = impl.get_virtual_chain_name(testset=TESTSET) + ".db"

    return os.path.join(working_dir, lastblock_filename)


def get_lastblock_filename(impl=None):
    """
    Get the absolute path to the last-block file.
    """
    impl = get_impl(impl)

    working_dir = get_working_dir(impl=impl)
    lastblock_filename = impl.get_virtual_chain_name(testset=TESTSET) + ".lastblock"

    return os.path.join(working_dir, lastblock_filename)


def get_snapshots_filename(impl=None):
    """
    Get the absolute path to the chain's consensus snapshots file.
    """
    impl = get_impl(impl)

    working_dir = get_working_dir(impl=impl)
    snapshots_filename = impl.get_virtual_chain_name(testset=TESTSET) + ".snapshots"

    return os.path.join(working_dir, snapshots_filename)


def configure_multiprocessing(blockchain_opts, impl=None):
    """
    Given the set of blockchain options (i.e. the location of the blockchain server),
    come up with some good multiprocessing parameters.

    Return (number of processes, number of blocks per process)
    Return (None, None) if we could make no inferences from the blockchain opts.
    """

    if blockchain_opts is None:
        return (None, None)

    if blockchain_opts.has_key("multiprocessing_num_procs") and blockchain_opts.has_key("multiprocessing_num_blocks"):
        return blockchain_opts["multiprocessing_num_procs"], blockchain_opts["multiprocessing_num_blocks"]

    if blockchain_opts.get("blockchain_server", None) is None:
        return (None, None)

    if blockchain_opts["blockchain_server"] in ["localhost", "127.0.0.1", "::1"]:
        # running locally
        return (1, 10)

    else:
        # running remotely
        return (10, 1)


def get_implementation():
    """
    Get the globally-set implementation of the virtual chain state.
    """
    global IMPL
    return IMPL


def set_implementation(impl, testset):
    """
    Set the package, class, or bundle of methods
    that implements the virtual chain's core logic.
    This method must be called before anything else.
    """
    global TESTSET
    global IMPL

    IMPL = impl
    TESTSET = testset


def import_blockchain( blockchain_name ):
    """
    Import the blockchain package we want, and make sure
    all the required methods are there.
    Return the (module, config) on success
    Raise an exception on error
    """

    # override the blockchain connection factory (for testing)
    blockchain_connect_override_module = os.getenv("VIRTUALCHAIN_MOD_BLOCKCHAIN")
    if blockchain_connect_override_module is not None:

        log.debug("Using '%s' to implement blockchain library" % blockchain_connect_override_module)

        # either compiled or source...
        mod_type = None
        if blockchain_connect_override_module.endswith(".pyc"):
            mod_type = imp.PY_COMPILED
        elif blockchain_connect_override_module.endswith(".py"):
            mod_type = imp.PY_SOURCE
        else:
            raise Exception("Unsupported module type: '%s'" % blockchain_connect_override_module)

        # find and load the module with the desired 'connect_blockchain' method
        mod_fd = open(blockchain_connect_override_module, "r")
        blockchain_mod = imp.load_module("mod_blockchain", mod_fd, blockchain_connect_override_module, ("", 'r', mod_type))

        try:
            process_local_connect_blockchain = blockchain_mod.connect_blockchain
            assert callable(process_local_connect_blockchain)
        except Exception, e:
            log.exception(e)
            raise Exception("Module '%s' has no callable 'connect_blockchain' method" % blockchain_connect_override_module)

        return blockchain_mod

    else:
        blockchain_package = "virtualchain.lib.blockchain.%s" % blockchain_name
        blockchain_mod = importlib.import_module(blockchain_package)

    for sym in BLOCKCHAIN_MOD_PROTOTYPE:
        assert hasattr(blockchain_mod, sym), "Missing symbol in %s: %s" % (blockchain_package, sym)
        assert type(getattr(blockchain_mod, sym)) in BLOCKCHAIN_MOD_PROTOTYPE[sym], "Wrong symbol type for %s in %s: %s" % (sym, blockchain_package, type(getattr(blockchain_mod, sym)))

    # tag it with our own information 
    blockchain_mod.__blockchain_name__ = blockchain_name
    return blockchain_mod


def get_blockchain_config( blockchain_name, config_path ):
    """
    Get the config for a blockchain
    """
    blockchain_mod = import_blockchain(blockchain_name)
    conf = blockchain_mod.get_blockchain_config( config_path )
    return conf 


def parse_blockchain_args( blockchain_name, return_parser=False, parser=None, impl=None, config_file=None ):
    """
    Parse blockchain-specific arguments on the command-line.
    Options correspond to valid config options returned by the blockchain-specific get_blockchain_config
    """
    
    impl = get_impl(impl)
    if config_file is None:
        config_file = get_config_file(impl=impl)
    
    conf = get_blockchain_config(blockchain_name, config_file)
    opts = {}
    accepted_args = []

    if parser is None:
        parser = argparse.ArgumentParser(description='%s version %s' % (impl.get_virtual_chain_name(testset=TESTSET), impl.get_virtual_chain_version()))

    for key in conf:
        if key in BLOCKCHAIN_CONFIG_REQUIRED_VALUES:
            continue

        accepted_args.append(key)
        parser.add_argument("--" + key, help="")

    for argname in accepted_args:
        if hasattr(args, argname) and getattr(args, argname) is not None:
            opts[argname] = getattr(args, argname)

    if return_parser:
        return opts, parser
    else:
        return opts

