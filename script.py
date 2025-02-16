#!/usr/bin/env python3
import logging
import re

import mitmproxy
from mitmproxy import http
from mitmproxy import tls
from mitmproxy import connection

DISABLE_TLS_INSPECTION = False
HTTP1_ADDRESSES = [] # Add regex patterns here
HTTP2_ADDRESSES = [] # Add regex patterns here
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

    if DISABLE_TLS_INSPECTION:
        data.ignore_connection = True
        return


_callback = mitmproxy.addons.tlsconfig.alpn_select_callback
logging.info("Overriding alpn_select_callback")


def _new_callback(*args, **kwargs):
    conn = args[0]
    sni = conn.get_servername().decode("utf-8")

    if any(pattern.match(sni) for pattern in HTTP1_WHITELIST):
        logging.info(f"Calling: {sni} set http2 to False")
        return b"http/1.1"

    return _callback(*args, **kwargs)


mitmproxy.addons.tlsconfig.alpn_select_callback = _new_callback


def is_whitelisted(sni, whitelist):
    """Check if the SNI matches any regex pattern in the whitelist."""
    return any(pattern.match(sni) for pattern in whitelist)


def request(flow: http.HTTPFlow):
    # Get the host of the request
    host = flow.request.host
    sni = IP_TO_SNI_MAP.get(host, host)

    if is_whitelisted(sni, HTTP1_WHITELIST):
        if flow.request.is_http10 or flow.request.is_http11:
            logging.info(f"HTTP1 passthrough: {host}.")
            return
        logging.info(f"HTTP1 passthrough: {host} is allowed only HTTP1 communication but was communicating in HTTP2, blocking.")
    elif is_whitelisted(sni, HTTP2_WHITELIST):
        return

    logging.info(f"Blocking request to {sni} ip: {host}.")
    flow.response = http.Response.make(
        403,  # HTTP status code for Forbidden
        b"This domain is not allowed.",  # Response body
        {"Content-Type": "text/plain"}  # Headers
    )

