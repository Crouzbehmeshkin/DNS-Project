from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from SocketManager.SocketManager import SocketManager
import datetime


class CA:

    def __init__(self, HOST, PORT):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.certs = dict()
        self.client_server = SocketManager(HOST, PORT)

    def run(self):
        '''
            you should send (host, port, message) as binary message to CA
            after that, we convert it to object in run function
        '''
        data = self.client_server.receive_message()
        host, port, message = self.client_server.convert_to_obj(data)

    def send_cert(self, target_host, target_port, csr):
        '''
            use run function to get host, port, csr and then in this function you can send cert to host and port
        '''

        subject = csr.subject
        issuer = csr.subject

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(self.key, hashes.SHA256())

        # add cert to self.certs
        self.certs[cert.public_key] = cert

        cert_binary = self.client_server.convert_to_binary(cert)

        self.client_server.send_message(target_host, target_port, cert_binary)

    def send_public_key(self, target_host, target_post):
        '''
            use run function firts to get host, port and after that send you public_key to that host and port
        '''

        self.client_server.send_message(target_host, target_post, self.key.public_key())