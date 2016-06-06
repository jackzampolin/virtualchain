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


import argparse
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import ssl
import threading
import time
import socket
from bitcoinrpc.authproxy import AuthServiceProxy
from utilitybelt import is_valid_int
from ConfigParser import SafeConfigParser

# how many blocks per hour?
AVERAGE_BLOCKS_PER_HOUR = 6

# various SSL compat measures
create_ssl_authproxy = False 
do_wrap_socket = False

if hasattr( ssl, "_create_unverified_context" ):
   ssl._create_default_https_context = ssl._create_unverified_context
   create_ssl_authproxy = True 

if not hasattr( ssl, "create_default_context" ):
   create_ssl_authproxy = False
   do_wrap_socket = True


# disable debug logging from bitcoinrpc
bitcoinrpc_logger = logging.getLogger("BitcoinRPC")
bitcoinrpc_logger.setLevel(logging.CRITICAL)

class BitcoindConnection( httplib.HTTPSConnection ):
   """
   Wrapped SSL connection, if we can't use SSLContext.
   """

   def __init__(self, host, port, timeout=None ):
   
      httplib.HTTPSConnection.__init__(self, host, port )
      self.timeout = timeout
        
   def connect( self ):
      
      sock = socket.create_connection((self.host, self.port), self.timeout)
      if self._tunnel_host:
         self.sock = sock
         self._tunnel()
         
      self.sock = ssl.wrap_socket( sock, cert_reqs=ssl.CERT_NONE )
      

def create_bitcoind_connection( rpc_username, rpc_password, server, port, use_https, timeout ):
    """
    Creates an RPC client to a bitcoind instance.
    It will have ".opts" defined as a member, which will be a dict that stores the above connection options.
    """
    
    global do_wrap_socket, create_ssl_authproxy
        
    protocol = 'https' if use_https else 'http'
    if not server or len(server) < 1:
        raise Exception('Invalid bitcoind host address.')
    if not port or not is_valid_int(port):
        raise Exception('Invalid bitcoind port number.')
    
    authproxy_config_uri = '%s://%s:%s@%s:%s' % (protocol, rpc_username, rpc_password, server, port)
    
    if use_https:
        # TODO: ship with a cert
        if do_wrap_socket:
           # ssl._create_unverified_context and ssl.create_default_context are not supported.
           # wrap the socket directly 
           connection = BitcoindConnection( server, int(port), timeout=timeout )
           ret = AuthServiceProxy(authproxy_config_uri, connection=connection)
           
        elif create_ssl_authproxy:
           # ssl has _create_unverified_context, so we're good to go 
           ret = AuthServiceProxy(authproxy_config_uri, timeout=timeout)
        
        else:
           # have to set up an unverified context ourselves 
           ssl_ctx = ssl.create_default_context()
           ssl_ctx.check_hostname = False
           ssl_ctx.verify_mode = ssl.CERT_NONE
           connection = httplib.HTTPSConnection( server, int(port), context=ssl_ctx, timeout=timeout )
           ret = AuthServiceProxy(authproxy_config_uri, connection=connection)
          
    else:
        ret = AuthServiceProxy(authproxy_config_uri)

    # remember the options 
    bitcoind_opts = {
       "bitcoind_user": rpc_username,
       "bitcoind_passwd": rpc_password,
       "bitcoind_server": server,
       "bitcoind_port": port,
       "bitcoind_use_https": use_https,
       "bitcoind_timeout": timeout
    }
    
    setattr( ret, "opts", bitcoind_opts )
    return ret


def connect_bitcoind_impl( bitcoind_opts ):
    """
    Create a connection to bitcoind, using a dict of config options.
    """
    return create_bitcoind_connection( bitcoind_opts['bitcoind_user'], bitcoind_opts['bitcoind_passwd'], \
                                       bitcoind_opts['bitcoind_server'], int(bitcoind_opts['bitcoind_port']), \
                                       bitcoind_opts['bitcoind_use_https'], float(bitcoind_opts.get('bitcoind_timeout', 300)) )
 

def get_bitcoind_config(config_file):
    """
    Set bitcoind options globally.
    Call this before trying to talk to bitcoind.
    Returns {} if no 'bitcoind' setion could be loaded
    """

    bitcoind_server = 'bitcoin.blockstack.com'
    bitcoind_port = '8332'
    bitcoind_user = 'blockstack'
    bitcoind_passwd = 'blockstacksystem'
    bitcoind_use_https = False
    bitcoind_mock = False
    bitcoind_timeout = 300
    bitcoind_mock_save_file = None

    assert config_file is not None

    parser = SafeConfigParser()
    parser.read(config_file)

    if parser.has_section('bitcoind'):

        if parser.has_option('bitcoind', 'server'):
            bitcoind_server = parser.get('bitcoind', 'server')

        if parser.has_option('bitcoind', 'port'):
            bitcoind_port = int(parser.get('bitcoind', 'port'))

        if parser.has_option('bitcoind', 'user'):
            bitcoind_user = parser.get('bitcoind', 'user')

        if parser.has_option('bitcoind', 'passwd'):
            bitcoind_passwd = parser.get('bitcoind', 'passwd')

        if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
        else:
            use_https = 'no'

        if parser.has_option("bitcoind", "save_file"):
            bitcoind_mock_save_file = parser.get("bitcoind", "save_file")

        if parser.has_option('bitcoind', 'mock'):
            mock = parser.get('bitcoind', 'mock')
        else:
            mock = 'no'

        if parser.has_option('bitcoind', 'timeout'):
            bitcoind_timeout = float(parser.get('bitcoind', 'timeout'))

        if use_https.lower() in ["yes", "y", "true", "1", "on"]:
            bitcoind_use_https = True
        else:
            bitcoind_use_https = False

        if mock.lower() in ["yes", "y", "true", "1", "on"]:
            bitcoind_mock = True
        else:
            bitcoind_mock = False
        
    else:
        return {}

    bitcoin_opts = {
        "bitcoind_user": bitcoind_user,
        "bitcoind_passwd": bitcoind_passwd,
        "bitcoind_server": bitcoind_server,
        "bitcoind_port": bitcoind_port,
        "bitcoind_use_https": bitcoind_use_https,
        "bitcoind_timeout": bitcoind_timeout,
        "bitcoind_mock": bitcoind_mock,
        "bitcoind_mock_save_file": bitcoind_mock_save_file,
        
        # for virtualchain
        "blockchain": "bitcoin",
        "blockchain_server": bitcoind_server,
        "blockchain_port": bitcoind_port
    }

    return bitcoin_opts


