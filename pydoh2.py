"""
DoH JSON client in Python with Flask API
"""

import json
import urllib3
import sys
import argparse
import socket
import signal
import random
from flask import Flask, request, jsonify

# Flask приложение
app = Flask(__name__)

# noinspection PyShadowingBuiltins, PyUnusedLocal
def handler(sgn, frame):
    """

    :param sgn:
    :param frame:
    :return:
    """
    sys.exit(0)


# noinspection PyShadowingBuiltins, PyUnusedLocal
def build_request(name, rr_type="A",
                  disable_dnssec=False,
                  content_type="",
                  include_dnssec_records=False,
                  edns_client_subnet="0.0.0.0/0",
                  random_padding=""):
    """
    https://developers.google.com/speed/public-dns/docs/doh/json

    :param str name: ASCII. The only required parameter. RFC 4343 backslash escapes are accepted.
                 Length must be between 1 and 253, ignoring optional trailing dot, if present.
                 All labels must be between 1 and 63 bytes.
                 Non-ASCII characters should be punycoded (e.g, xn--qxam, not ελ).

    :param str rr_type: RR type. Default 1. Can be [1, 65535] or case-insensitive canonical string (e.g., A or aaaa).
                    255 = ANY

    :param bool disable_dnssec: Checking disabled. Use cd=1 to disable DNSSEC validation

    :param str content_type: Default application/x-javascript for JSON. Use application/dns-message for binary DNS.

    :param bool include_dnssec_records: DNSSEC OK flag. If true, include RRSIG, NSEC, NSEC3 records; otherwise, omit.

    :param str edns_client_subnet: If you are using DNS-over-HTTPS because of privacy concerns, and do not want any part
                                   of your IP address to be sent to authoritative name servers for geographic location
                                   accuracy, use edns_client_subnet=0.0.0.0/0
    :param str random_padding: ignored
    :return str:
    """

    cloudflare_part = "https://cloudflare-dns.com/dns-query"
    google_part = "https://dns.google/resolve"

    server_part = google_part

    fields = []
    if rr_type:
        fields.append("type=%s" % rr_type)

    if disable_dnssec:
        fields.append("cd=true")

    if content_type and server_part == google_part:
        fields.append("ct=%s" % content_type)

    if include_dnssec_records:
        fields.append("do=true")

    if edns_client_subnet and server_part == google_part:
        fields.append("edns_client_subnet=%s" % edns_client_subnet)

    if fields:
        query = "%s?name=%s&%s" % (server_part, name, "&".join(fields))
    else:
        query = "%s?name=%s" % (server_part, name)

    return query


def make_request(req):
    """

    :param req:
    :return:
    """

    https = urllib3.PoolManager()

    # cloudflare needs this, google ignores it
    r = https.request("GET", req, headers={"accept": "application/dns-json"})
    print(r.status)
    print(req)
    if r.status == 200:
        # print(r.headers)
        # not checking Content-Type in header...
        d = json.loads(r.data)
        print(d)


def make_post(query):
    """

    :param query:
    :return:
    """
    https = urllib3.PoolManager()
    """
    >>> http = urllib3.PoolManager(
    ...     cert_reqs='CERT_REQUIRED',
    ...     ca_certs='/path/to/your/certificate_bundle')    
    """

    # test data
    # body = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x65\x78\x61\x6d
    # \x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'

    # you have to update hosts file so dns.google points to 8.8.4.4 and cloudflare-dns.com points to 104.16.249.249

    urls = ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"]
    r = https.request("POST", random.choice(urls), headers={"Content-Type": "application/dns-message"},
                      body=query)

    if r.status == 200:
        return r.data
    else:
        print(r.status)


def main():
    """

    :return:
    """
    parser = argparse.ArgumentParser(description="Retrieves DNS records for a name.",
                                     epilog="Example: python dnsclient.py google.com.")

    parser.add_argument("name", help="Name to query")
    parser.add_argument("--type", help="RR type. Default A", default='A')
    parser.add_argument("--dnssec", help="Use DNS sec", default=True, type=bool)
    parser.add_argument("--content-type",
                        help="Content-type: application/x-javascript. For binary DNS use application/dns-message.",
                        default="application/x-javascript", type=str,
                        choices=["application/x-javascript", "application/dns-message"])

    parser.add_argument("--do", help="DNSSEC OK. Return records if true",
                        type=bool,
                        default=False)

    parser.add_argument("--ednsclientsub", help="edns0-client-subnet. Default 0.0.0.0/0 for privacy.",
                        type=str,
                        default="0.0.0.0/0")

    args = parser.parse_args()

    req = build_request(args.name, args.type, not args.dnssec, args.content_type, args.do, args.ednsclientsub)
    make_request(req)


def udp_server():
    """

    :return:
    """

    address = '127.0.0.1'
    port = 53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    s.bind(server_address)
    s.settimeout(1)
    signal.signal(signal.SIGINT, handler)
    print("DoH! Server")
    print("Make sure hosts file correctly points google.dns and cloudflare-dns.com"
          " to 8.8.4.4. and 104.16.249.249, respectively.")
    print("Started on %s:%d..." % (address, port))
    while True:
        try:
            query, address = s.recvfrom(4096)
            if query:
                answer = make_post(query)
                s.sendto(answer, address)
        except socket.timeout:
            pass
        except WindowsError as we:
            if we.errno == 10054:
                # remote host closed connection.
                pass
            else:
                print(we)
        except Exception as e:
            print(e)

# Flask API endpoint
@app.route("/doh", methods=["GET"])
from flask import Response

@app.route("/dns-query", methods=["GET", "POST"])
def dns_query():
    if request.method == "GET":
        dns_query_data = request.args.get("dns")
        if not dns_query_data:
            return "Missing 'dns' parameter", 400
        import base64
        try:
            decoded = base64.urlsafe_b64decode(dns_query_data + '==')
        except Exception as e:
            return f"Invalid base64: {e}", 400
        response = make_post(decoded)
        return Response(response, content_type="application/dns-message")

    elif request.method == "POST":
        if request.content_type != "application/dns-message":
            return "Unsupported Media Type", 415
        dns_query_data = request.get_data()
        response = make_post(dns_query_data)
        return Response(response, content_type="application/dns-message")
def doh_query():
    name = request.args.get("name", "")
    rr_type = request.args.get("type", "A")

    if not name:
        return jsonify({"error": "Missing 'name' parameter"}), 400

    url = build_request(name, rr_type)
    https = urllib3.PoolManager()
    r = https.request("GET", url, headers={"accept": "application/dns-json"})

    if r.status == 200:
        return jsonify(json.loads(r.data))
    else:
        return jsonify({"error": f"Request failed with status {r.status}"}), r.status

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "message": "DoH server is running"}), 200


if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
    print("Exiting....")
