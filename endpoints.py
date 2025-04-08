#!/usr/bin/env python3
import logging
import re

import mitmproxy
from mitmproxy import http
from mitmproxy import tls
from mitmproxy import connection

DISABLE_TLS_INSPECTION = False
HTTP1_ADDRESSES = [r"^agent\..*\.app\.wiz\.io$"]
HTTP2_ADDRESSES = [
    r"^auth\.app\.wiz\.io$", 
    r"^wizio\.azurecr\.io$", 
    r"^.*\.wizio\.azurecr\.io$", 
    r"^wiziopublic\.azurecr\.io$",  # Add wiziopublic.azurecr.io explicitly
    r"^registry\.wiz\.io$",
    r"^.*\.registry\.wiz\.io$",
    r"^public-registry\.wiz\.io$",
    r"^.*\.public-registry\.wiz\.io$"
]
HTTP1_WHITELIST = [re.compile(pattern) for pattern in HTTP1_ADDRESSES]
HTTP2_WHITELIST = [re.compile(pattern) for pattern in HTTP2_ADDRESSES]
IP_TO_SNI_MAP = dict()


def get_addr(server: connection.Server):
    # .peername may be unset in upstream proxy mode, so we need a fallback.
    return server.peername or server.address


def tls_clienthello(data: tls.ClientHelloData):
    server_address = get_addr(data.context.server)
    sni = data.client_hello.sni
    IP_TO_SNI_MAP[server_address[0]] = sni
    
    logging.info(f"TLS ClientHello: SNI={sni}, Address={server_address[0]}")
    
    # Log the ALPN protocols offered by the client
    alpn_protocols = data.client_hello.alpn_protocols
    if alpn_protocols:
        logging.info(f"Client offered ALPN protocols: {alpn_protocols}")
    
    if DISABLE_TLS_INSPECTION:
        logging.info(f"TLS inspection disabled for {sni}")
        data.ignore_connection = True
        return


_callback = mitmproxy.addons.tlsconfig.alpn_select_callback
logging.info("Overriding alpn_select_callback")


def _new_callback(*args, **kwargs):
    conn = args[0]
    sni = conn.get_servername().decode("utf-8")
    
    logging.info(f"ALPN callback for: {sni}")
    
    # Check for HTTP1 domains
    if any(pattern.match(sni) for pattern in HTTP1_WHITELIST):
        logging.info(f"Forcing HTTP/1.1 for: {sni}")
        return b"http/1.1"
    
    # Check for registry and ACR domains first (more specific check)
    if ('registry.wiz.io' in sni or 
        'public-registry.wiz.io' in sni or 
        'wiziopublic.azurecr.io' in sni or
        'wizio.azurecr.io' in sni):
        logging.info(f"Allowing HTTP/2 for registry/ACR domain: {sni}")
        return b"h2"
    
    # Check other HTTP2 domains
    if any(pattern.match(sni) for pattern in HTTP2_WHITELIST):
        logging.info(f"Allowing HTTP/2 for: {sni}")
        return b"h2"
    
    # For domains not in either whitelist, use the default behavior
    logging.info(f"Using default ALPN for: {sni}")
    return _callback(*args, **kwargs)


mitmproxy.addons.tlsconfig.alpn_select_callback = _new_callback


def is_whitelisted(sni, whitelist):
    """Check if the SNI matches any regex pattern in the whitelist."""
    return any(pattern.match(sni) for pattern in whitelist)


def request(flow: http.HTTPFlow):
    host = flow.request.host
    sni = IP_TO_SNI_MAP.get(host, host)
    
    logging.info(f"Processing request: {flow.request.url}")
    logging.info(f"SNI: {sni}, IP: {host}")
    
    # Special case for registry and ACR domains - CHECK THIS FIRST
    if ('registry.wiz.io' in sni or 
        'public-registry.wiz.io' in sni or 
        'wiziopublic.azurecr.io' in sni or
        'wizio.azurecr.io' in sni):
        logging.info(f"Registry/ACR domain passthrough: {sni}")
        # Log the protocol being used
        protocol = "HTTP/2" if flow.request.http_version == "HTTP/2.0" else f"HTTP/{flow.request.http_version}"
        logging.info(f"Protocol for {sni}: {protocol}")
        return
    
    # Check if domain is in HTTP1_WHITELIST
    elif is_whitelisted(sni, HTTP1_WHITELIST):
        if flow.request.is_http10 or flow.request.is_http11:
            logging.info(f"HTTP/1 passthrough: {sni}")
            return
        logging.info(f"Blocking {sni} - HTTP/1 only domain using HTTP/2")
        flow.response = http.Response.make(
            400,
            b"This domain requires HTTP/1.x",
            {"Content-Type": "text/plain"}
        )
    # Special case for registry domains with more detailed logging
    elif 'registry.wiz.io' in sni or 'public-registry.wiz.io' in sni:
        logging.info(f"Registry domain passthrough: {sni}")
        # Log the protocol being used
        protocol = "HTTP/2" if flow.request.http_version == "HTTP/2.0" else f"HTTP/{flow.request.http_version}"
        logging.info(f"Protocol for {sni}: {protocol}")
        return
    # Check if domain is in HTTP2_WHITELIST
    elif is_whitelisted(sni, HTTP2_WHITELIST):
        logging.info(f"HTTP/2 passthrough: {sni}")
        return
    else:
        logging.info(f"Blocking request to non-whitelisted domain: {sni}")
        flow.response = http.Response.make(
            403,
            b"This domain is not allowed.",
            {"Content-Type": "text/plain"}
        )
