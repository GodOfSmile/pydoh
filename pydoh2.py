import json
import urllib3
import sys
import argparse
import socket
import signal
import random
from flask import Flask, request, jsonify, Response
import base64
import threading

# Flask приложение
app = Flask(__name__)

# noinspection PyShadowingBuiltins, PyUnusedLocal
def handler(sgn, frame):
    sys.exit(0)

def build_request(name, rr_type="A", disable_dnssec=False, content_type="", include_dnssec_records=False,
                  edns_client_subnet="0.0.0.0/0", random_padding=""):
    """
    Строит запрос для DoH-сервера.
    :param str name: Имя для запроса.
    :param str rr_type: Тип RR. По умолчанию A.
    :param bool disable_dnssec: Отключить DNSSEC.
    :param str content_type: Тип контента для запроса.
    :param bool include_dnssec_records: Включить DNSSEC записи.
    :param str edns_client_subnet: Клиентский адрес для улучшения географической точности.
    :param str random_padding: Случайные данные для запроса.
    :return str: Строка запроса.
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
    Выполняет GET-запрос к DoH-серверу.
    :param req: URL для запроса.
    :return: Ответ от сервера в виде JSON.
    """
    https = urllib3.PoolManager()
    r = https.request("GET", req, headers={"accept": "application/dns-json"})
    print(r.status)
    print(req)
    if r.status == 200:
        d = json.loads(r.data)
        print(d)

def make_post(query):
    """
    Выполняет POST-запрос к DoH-серверу.
    :param query: Тело запроса.
    :return: Ответ от сервера в виде байтов.
    """
    https = urllib3.PoolManager()
    urls = ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"]
    r = https.request("POST", random.choice(urls), headers={"Content-Type": "application/dns-message"}, body=query)

    if r.status == 200:
        return r.data
    else:
        print(r.status)

def udp_server():
    """
    Сервер UDP для DoH-запросов.
    """
    address = '127.0.0.1'
    port = 53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    s.bind(server_address)
    s.settimeout(1)
    signal.signal(signal.SIGINT, handler)
    print("DoH! Server started on %s:%d..." % (address, port))
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
                pass
            else:
                print(we)
        except Exception as e:
            print(e)

@app.route("/doh", methods=["GET"])
def doh_query():
    """
    Обработчик для DoH запросов.
    :return: Ответ в виде JSON.
    """
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

@app.route("/dns-query", methods=["GET", "POST"])
def dns_query():
    """
    Основной обработчик DoH-запросов через GET и POST.
    """
    if request.method == "GET":
        dns_query_data = request.args.get("dns")
        if not dns_query_data:
            return "Missing 'dns' parameter", 400
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

@app.route("/health", methods=["GET"])
def health_check():
    """
    Проверка состояния сервера.
    :return: Статус сервера.
    """
    return jsonify({"status": "ok", "message": "DoH server is running"}), 200

def run_udp_server():
    """
    Запуск UDP-сервера в фоне.
    """
    udp_thread = threading.Thread(target=udp_server)
    udp_thread.daemon = True
    udp_thread.start()

if __name__ == "__main__":
    import os
    run_udp_server()  # Запуск UDP-сервера в фоне
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
    print("Exiting....")
