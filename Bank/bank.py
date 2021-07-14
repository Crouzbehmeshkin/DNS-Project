import threading

import numpy as np
import socket
import threading
import time
import pickle
import random
import math as m
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from utils.currency_change import *


class BANK(threading.Thread):
    # todo: we should put a zero balance (accounts[pub_key] = 0) for every new user and merchant introduced

    def __init__(self, id, location, n):

        threading.Thread.__init__(self)

        self.Users = []
        self.info = []
        self.user_ack = []
        self.name = 'bank'
        self.accounts = {}
        self.exchanger = 0  # have to set this to pub_key of exchanger

        self.pri_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_key = self.pri_key.public_key()
        self.certificate = 0

        self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])).add_extension(
            x509.SubjectAlternativeName([

                x509.DNSName(u"mysite.com"),
                x509.DNSName(u"www.mysi.com"),
                x509.DNSName(u"domain.mysite.com"),
            ]),
            critical=False,

        ).sign(self.pri_key, hashes.SHA256())

    def L_merchant(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 7920))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'request_balance':
                        merchant_pub_key = kc['value'][0]
                        authenticated = True  # should really authenticate the merchant pubkey and sig
                        if authenticated:
                            self.send_bank_balance(merchant_pub_key)

                if not data1:
                    break

    def send_bank_balance(self, account_pub_key):
        data = {}

        data['type'] = "balance_response"
        # sig = None
        data['value'] = [self.accounts[account_pub_key], self.pub_key, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8000))
        s.sendall(x)
        s.close()

    def L_block(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 6700))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'exchnger_got_paid':
                        payment_id = kc['value'][0]
                        self.finalize_payment(payment_id)

                if not data1:
                    break

    def L_USER(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 8000))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'Account_bank':
                        self.Users.append(kc['value'][1])
                        a = random.randint(1000, 10000)
                        self.info.append(kc['value'][2], a)

                        self.user_ack.append((a, kc['value'][0]))

                    if kc['type'] == 'CA certificate':
                        self.certificate = kc['value'][0]

                    if kc['type'] == 'payment':
                        self.payments.append(kc['value'])
                        self.pay_to_exchanger(kc['value'])

                if not data1:
                    break

        return

    def pay_to_exchanger(self, payment_info):
        user_pub_key = payment_info[0]
        amount = payment_info[1]
        merchant_pub_key = payment_info[2]

        data = {};

        data['type'] = "deligated_payment"
        # sig = None
        payment_id = len(self.payments)
        data['value'] = [self.pub_key, self.name, sig, user_pub_key, amount, payment_id]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 6000))
        s.sendall(x)
        s.close()

    def finalize_payment(self, payment_id):
        payment_info = self.payments[payment_id]
        user = payment_info[0]
        amount = crypto_to_fiat(payment_info[1])
        merchant = payment_info[2]
        self.accounts[merchant] += amount
        self.accounts[self.exchanger] -= amount


def send(self):
    data = {}

    data['type'] = "CA certificate"
    sig = self.pri_key.sign(self.csr.public_bytes(serialization.Encoding.PEM),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
    data['value'] = [sig, self.pub_key, self.csr, 8001, self.name]

    x = pickle.dumps(data)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 7000))
    s.sendall(x)
    s.close()
    while True:

        if self.user_ack:
            self.enod_sgw_c = 0
            data = {};

            data['type'] = "account_ack"
            data['value'] = self.user_ack[0]
            self.user_ack.pop(0)
            x = pickle.dumps(data)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', data['value'][1]))
            s.sendall(x)
            s.close()


def run1(self):
    t = []

    t1 = threading.Thread(target=self.l_sgw)
    t2 = threading.Thread(target=self.send)
    t3 = threading.Thread(target=self.l_mme)
    t4 = threading.Thread(target=self.l_data)
    t5 = threading.Thread(target=self.l_sig)
    t2.start()
    t1.start()
    t3.start()
    t4.start()
    t5.start()
    t.append(t1)
    t.append(t2)
    t.append(t3)
    t.append(t4)
    t.append(t5)

    for n in t:
        n.join()