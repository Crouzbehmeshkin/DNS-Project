from datetime import datetime

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

CA_HOST = "127.0.0.1"
CA_PORT = 9001

BANK_HOST = "127.0.0.1"
BANK_PORT = 9002

MERCHANT_HOST = "127.0.0.1"
MERCHANT_PORT = 9003

CUSTOMER_HOST = "127.0.0.1"
CUSTOMER_PORT = 9004

EXCHANGE_HOST = "127.0.0.1"
EXCHANGE_PORT = 9005


class BLOCKCHAIN(threading.Thread):

    def __init__(self, id, location, n, exchanger_account, bank_account_told_to_exchanger):

        threading.Thread.__init__(self)

        self.CA_req = []
        self.user = []
        self.user_Ack = []
        self.deligations = {}
        self.accounts = {}
        self.exchanger_account = exchanger_account
        self.account_e = bank_account_told_to_exchanger

    def L_bank(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 6000))
        sock.listen(10)

        while True:

            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024);

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'crypto_sell_req':
                        authenticated = True  # todo should put the correct requirements to verify bank identity like balance of the account or validity of deligated rights
                        user_pub_key = kc['value'][0]
                        bank_pub_key = kc['value'][1]
                        amount = kc['value'][2]
                        transaction_id = kc['value'][-1]

                        if authenticated:
                            self.accounts[user_pub_key] -= amount
                            self.accounts[self.exchanger_account] += amount
                            self.sell_transaction_approved(amount, user_pub_key, bank_pub_key, transaction_id)

                if not data1:
                    break

        return

    def sell_transaction_approved(self, amount, user_pub_key, bank_pub_key, transaction_id):
        data = {}
        data['type'] = "sell_transaction_approved"
        data['value'] = [amount, user_pub_key, bank_pub_key, self.account_e, datetime.now(), transaction_id]
        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 6700))
        s.sendall(x)
        s.close()

    def L_USER(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 7500))
        sock.listen(10)

        while True:

            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024);

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'Account_block':
                        kc['value'][1].verify(kc['value'][0], kc['value'][2].public_bytes(serialization.Encoding.PEM),
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                        self.CA_req.append(kc['value'])

                        self.user.append((kc['value'][1], kc['value'][4]))

                    if kc['type'] == 'deligation':
                        primary_owner = kc['value'][1]
                        secondary_owner = kc['value'][0]
                        policy = kc['value'][2]
                        authenticated = True  # check authentication
                        if authenticated:
                            self.deligations[primary_owner] = [secondary_owner, policy]

                if not data1:
                    break

        return

    def L_CA(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 7000))
        sock.listen(10)

        while True:

            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024);

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'CA_certificate':
                        self.user_Ack.append(kc['value'])

                if not data1:
                    break;

        return

    def send(self):

        while True:

            if self.CA_req:
                data = {};

                data['type'] = "CA certificate"
                data['value'] = self.CA_req[0]
                self.CA_req.pop[0]
                x = pickle.dumps(data)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', 8000))
                s.sendall(x)
                s.close()

            if self.user_Ack:
                data = {};

                data['type'] = "Account_Ack"
                data['value'] = self.user_Ack[0]
                self.user_Ack.pop[0]
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