import socket


def __init__(self, host, port):
    self.host = host
    self.port = port
    self.cert = None
    self.key = None


def receive_message(self):
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

                message = data.decode('utf-8')
                print(message)

                return message


def send_message(self, HOST, PORT, message):
    '''
        HOST: target server host
        PORT: target server port
    '''

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))

        message_arr = bytes(message, 'utf-8')
        s.sendall(message_arr)

        # hand shake, not necessary
        data = s.recv(1024)

        if data == message_arr:
            print('True handshake')

        else:
            print('False handshake')


def send_with_ssl(self, host, port, message):
    pass


def receive_with_ssl(self):
    pass