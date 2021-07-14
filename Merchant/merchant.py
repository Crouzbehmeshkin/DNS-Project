import hashlib
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


class MERCHANT(threading.Thread):
    # todo: we should request balance once in the initial state of the merchant for it to be correct

    def __init__(self, id, location, n):

        threading.Thread.__init__(self)
        self.user_ports = {}
        self.bank_pass = 0
        self.bank_balance = 0
        self.expected_balance = 0
        self.approved_transaction = False

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

    def L_bank(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 8000))
        sock.listen(10)

        while True:
            connection, client_address = sock.accept()

            while True:

                data1 = connection.recv(1024)

                if data1:

                    kc = pickle.loads(data1)

                    if kc['type'] == 'account_ack':
                        self.bank_pass = kc['value'][0]
                    # if kc['type'] == 'balance_response':
                    #     self.bank_balance = kc['value'][0]
                    #     self.check_payment()
                    if kc['type'] == 'money_transaction_approved':
                        account = kc['value'][0]
                        amount = kc['value'][1]
                        transaction_id = kc['value'][2]

                        self.approved_transaction = True
                        self.approve_user_payment(account, amount, transaction_id)
                        print("merchant approves transaction!")

                if not data1:
                    break;

        return
    def approve_user_payment(self, account, amount, transaction_id):
        data = {};
        sig = None
        data['type'] = "payment approved"

        data['value'] = [transaction_id, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7200))
        s.sendall(x)
        s.close()
        sig = None

    # def check_payment(self):
    #     if self.bank_balance == self.expected_balance:
    #         print("balance correct")
    #     else:
    #         print("balance not correct")

    def send(self):

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
                data = {}

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

    def payment_request(self, account, amount):
        self.approved_transaction = False
        self.amount = amount
        self.expected_balance = self.bank_balance + self.amount
        data = {}

        data['type'] = "payment_request"
        sig=None
        client_info = str(account) + str(random.randint(1000, 10000))
        transaction_id = hashlib.sha256((str(account) + str(amount) + str(client_info) + str(datetime.now())).encode('utf-8')).hexdigest()
        data['value'] = [self.pub_key, amount, transaction_id, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7200))
        s.sendall(x)
        s.close()


    def payment_approve(self, transaction_id):
        data = {}
        data['type'] = "payment_approved"
        sig = None

        data['value'] = [transaction_id, sig]

        x = pickle.dumps(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7990))
        s.sendall(x)
        s.close()


    # def request_bank_balance(self):
    #     data = {}
    #
    #     data['type'] = "request_balance"
    #     sig=None
    #     data['value'] = [self.pub_key, sig]
    #
    #     x = pickle.dumps(data)
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.connect(('127.0.0.1', 7920))
    #     s.sendall(x)
    #     s.close()

