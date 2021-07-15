import socket
import ssl
import pickle


class SocketManager:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.CA_bundle = None
        self.private_key = None

    def receive_message(self):
        '''
            data is binary
            you should convert it to obj by convert_to_obj function
        '''

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()

            print('server is listening...')
            # print(self.host, self.port)
            conn, addr = s.accept()

            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break

                    # hand shake, not necessary
                    conn.sendall(data)

                    # message = data.decode('utf-8')
                    # print(message)

                    return data

    def send_message(self, HOST, PORT, message):
        '''
            HOST: target server host
            PORT: target server port
            message must be binary. before this you can convert your object with convert_to_binary function
        '''

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.connect((HOST, PORT))

            s.sendall(message)

            # hand shake, not necessary
            data = s.recv(1024)

            if data == message:
                print('True handshake')

            else:
                print('False handshake')

    def receive_with_ssl(self, ca_bundle, key):
        '''
            ca_bundle: it is an address from ca_bundle and must be string
            key: it is key of any object that try to send message with ssl, it is an address
        '''

        self.ca_bundle = ca_bundle
        self.key = key

        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv = ssl.wrap_socket(serv, keyfile=key, certfile=ca_bundle, server_side=True)
        serv.bind((self.host, self.port))
        serv.listen()
        print('server is listening...')

        conn, addr = serv.accept()
        print('connected with ', addr)

        with conn:
            print('Connected by', addr)

            while True:
                from_client = conn.recv(4096)  # The received data type is byte, converted to str
                if not from_client:
                    break

                conn.send(from_client)  # Convert str to byte type, you need to use byte when transmitting

                conn.close()
                print('client diconnected')
                return from_client

    def send_with_ssl(self, ca_bundle, key, HOST, PORT, message):
        '''
            ca_bundle: it is an address from ca_bundle and must be string
            key: it is key of any object that try to send message with ssl, it is an address
            HOST: target host to send
            PORT: target port to send
            message: it must be binary.
        '''

        self.ca_bundle = ca_bundle
        self.key = key

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = ssl.wrap_socket(client, keyfile=key, certfile=ca_bundle, server_side=False)
        client.connect((HOST, PORT))

        client.send(message)

        from_server = client.recv(4096)

        if from_server == message:
            print('True handshake')
        else:
            print('False handshake')

        client.close()

    def convert_to_binary(self, obj):
        return pickle.dumps(obj)

    def convert_to_obj(self, binary):
        return pickle.loads(binary)