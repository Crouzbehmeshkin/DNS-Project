import datetime

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
from datetime import datetime
from dateutil.relativedelta import relativedelta

class USER(threading.Thread):

    def __init__(self, id, location, n, CID, password, merchant_pub_key):

        threading.Thread.__init__(self)

        self.pri_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_key = self.pri_key.public_key()
        self.certificate = 0
        self.bank_pass = 0
        self.amount = 0
        self.bank_public_key = 0
        self.CID = CID
        self.password = password
        self.merchant_pub_key = merchant_pub_key
        self.is_authenticated = False

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

    def L_CA(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 8000))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'CA certificate':
                        self.certificate = kc['value'][0]

                if not data1:
                    break

        return

    def L_Block(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 8001))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'CA certificate':
                        self.certificate = kc['value'][0]

                    if kc['type'] == 'Account_Ack':
                        self.certificate = kc['value'][0]

                if not data1:
                    break

        return
    def L_bank(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 6745))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'authentication_success':
                        CID = kc['value'][0]
                        if CID == self.CID:
                            self.is_authenticated = True

                if not data1:
                    break

        return


    def L_merchant(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 7200))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'payment_request':
                        merchant_pub_key_match = (kc['value'][0] == self.merchant_pub_key)
                        amount_match = (kc['value'][1] == self.amount)
                        if merchant_pub_key_match and amount_match:
                            merchant_account = kc['value'][0]
                            amount = kc['value'][1]
                            transaction_id = kc['value'][2]
                            self.pay(amount, merchant_account, transaction_id)
                        else:
                            raise Exception("payment info missmatch!")
                    if kc['type'] == 'payment approved':
                        print("user confirms payment approvement")
                if not data1:
                    break

        return

    def request_authentication(self):
        data = {}

        data['type'] = "request_authentication"
        data['value'] = [self.pub_key, self.CID, self.password]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8000))
        s.sendall(x)
        s.close()

    def pay(self, amount, merchant_pub_key, transaction_id):
        data = {}
        now = datetime.now()
        data['type'] = "payment"
        message = (str(self.pub_key) + str(merchant_pub_key) + str(amount) + str(transaction_id) + str(now)).encode('utf-8')
        sig = self.pri_key.sign(
        message,padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())

        data['value'] = [self.pub_key, merchant_pub_key, fiat_to_crypto(amount), transaction_id, now, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8000))
        s.sendall(x)
        s.close()

    def deligate(self, amount_allowed, merchant_pub_key,
                 last_valid_time=datetime.now() + relativedelta(months=+1), count_=10):
        data = {}

        policy = [amount_allowed, count_, last_valid_time, merchant_pub_key]

        data['type'] = "deligatation"
        message = (str(self.bank_public_key) + str(policy)).encode(
            'utf-8')
        sig = self.pri_key.sign(
            message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())


        data['value'] = [self.bank_public_key, self.pub_key, policy, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7500))
        s.sendall(x)
        s.close()

    def L_bank(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 8000))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024);

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'account_ack':
                        self.bank_pass = kc['value'][0]

                if not data1:
                    break;

        return

    def send(self):

        data = {}

        data['type'] = "Account_block"
        # sig = key.sign(self.csr.public_bytes(serialization.Encoding.PEM),
        #                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        #                hashes.SHA256())
        # data['value'] = [sig, self.pub_key, self.csr, 8001, self.name]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7000))
        s.sendall(x)
        s.close()

        data = {};

        data['type'] = "Account_bank"

        data['value'] = [8001, self.name, 100]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 9000))
        s.sendall(x)
        s.close()

        while True:

            if self.e:
                self.enod_sgw_c = 0
                data = {};

                data['type'] = "eNodeB-SGW connection"
                data['value'] = self.id
                x = pickle.dumps(data)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', self.p_sgw))
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

