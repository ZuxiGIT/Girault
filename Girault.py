import Defaults
from Logger import Logger
import MyCrypto
from pygroup.groups import Group

import socket
import threading
import random
#from Crypto.PublicKey import RSA

pdebug = Defaults.pdebug

log = Logger(Defaults.LogPath)


def serialize_name(name: str) -> bytes:
    hex_name = name.encode()
    return (Defaults.ID_LENGTH - len(hex_name)) * Defaults.ID_PADDING +\
        hex_name


def deserialize_name(int_bytes: bytes) -> str:
    last_padd = int_bytes.rfind(Defaults.ID_PADDING)
    if last_padd != -1:
        return int_bytes[last_padd+1:].decode('utf-8')
    return int_bytes.decode('utf-8')


def deserialize_name_to_int(int_bytes: bytes) -> int:
    last_padd = int_bytes.rfind(Defaults.ID_PADDING)
    if last_padd != -1:
        return int.from_bytes(int_bytes[last_padd+1:], byteorder='little')
    return int.from_bytes(int_bytes, byteorder='little')


def serialize_integer(secret: int) -> bytes:
    return secret.to_bytes((secret.bit_length() + 7) // 8, byteorder='little')


def deserialize_integer(int_bytes: bytes) -> int:
    return int.from_bytes(int_bytes, byteorder='little')


def name_to_integer(name: str) -> int:
    return int.from_bytes(name.encode(), byteorder='little')


class Server():
    def __init__(self, addr=Defaults.Addr, port=Defaults.Port):
        # self.rsa_provider = MyCrypto.RSA(bitlen=16)
        '''
        #(e, d, p, q, n) = self.rsa_provider.generate_keys()
        #self.pub_key = (e, n)
        #self.prv_key = (d, n)
        #self.g = self.find_group_generator(n)
        '''
        p = 919
        q = 839
        p*q
        n = 771041
        e = 53
        d = 420929
        g = 77
        self.e = e
        self.d = d
        self.n = n
        self.p = p
        self.q = q
        self.pub_key = (e, n)
        self.prv_key = (d, n)
        self.g = g
        self.clients_pub_keys = {}

        pdebug(f" e = {e}")
        pdebug(f" d = {d}")
        pdebug(f" n = {n}")
        pdebug(f" g = {self.g}")

        log.info("Ready to publish")
        log.info(f"e = {self.pub_key[0]}")
        log.info(f"n = {self.pub_key[1]}")
        log.info(f"g = {self.g}")

        self.addr = addr
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((addr, port))
        log.info(f"Server binded to {addr}:{port}")
        self.sock.listen()

        self.serve_forever()

    def find_group_generator(self, n):
        G = Group('mult', n)
        g = G.g()
        go = G.go()
        overall = list(zip(g, go))
        return max(overall, key=lambda pair: pair[1])[0]

    def serve_forever(self):
        while True:
            conn, client_addr = self.sock.accept()
            log.info(f"Established connection with {client_addr}")
            threading.Thread(target=self.handle_client,
                             args=(conn, client_addr)).start()

    def handle_client(self, conn, client_addr):
        while True:
            data = None
            while not data:
                data = conn.recv(Defaults.MESSAGE_LENGTH)

            # Send client's public key after authentication
            if data[:Defaults.MSG_CODE_LENGTH] == Defaults.GET_CLIENT_PUBLIC_KEY:
                log.info("Get message code: GET_CLIENT_PUBLIC_KEY")
                self.send_client_public_key(conn,
                                            data[Defaults.MSG_CODE_LENGTH:])

            if data[:Defaults.MSG_CODE_LENGTH] == Defaults.GET_PARAMETERS:
                self.send_client_parameters(conn)

    def authenticate_client(self, client_id):
        pass

    def generate_client_pub_key(self, client_id, v):
        i = deserialize_name_to_int(client_id)
        P = pow((v - i), self.d, self.n)
        self.clients_pub_keys[client_id] = P

    def send_client_public_key(self, conn, data):
        client_id = data[:Defaults.ID_LENGTH]
        v = deserialize_integer(data[Defaults.ID_LENGTH:])

        log.info(f"Client id: {client_id}")
        log.info("Authenticating client")
        self.authenticate_client(client_id)

        if client_id not in self.clients_pub_keys:
            log.info("Generating client's public key")
            self.generate_client_pub_key(client_id, v)
            log.info(f"Generated for client {deserialize_name(client_id)}"
                     f" public key: {self.clients_pub_keys[client_id]}")

        log.info("Sending client's public key")
        key = self.clients_pub_keys[client_id]
        key = key.to_bytes(key.bit_length() + 7 // 8, byteorder='little')
        conn.sendall(key)

    def send_client_parameters(self, conn):
        n = serialize_integer(self.n)
        e = serialize_integer(self.e)
        g = serialize_integer(self.g)

        conn.sendall(n + b'\x00'*5 + e + b'\x00'*5 + g)


class Client():
    def __init__(self, name):
        self.name = name
        self.id = serialize_name(name)
        self.secret = random.getrandbits(4)

    def recv_from_server(self):
        data = None
        while not data:
            data = self.sock.recv(Defaults.MESSAGE_LENGTH)
        return data

    def connect_to_server(self, addr, port):
        log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.info("Connecting to a server")
        self.sock.connect((addr, port))
        log.info("Connected to a server")

        log.info("Getting scheme parameters")
        self.fetch_parameters_from_server()
        log.info("Fetched parameters from server")

        log.info(f"n: {self.n}")
        log.info(f"e: {self.e}")
        log.info(f"g: {self.g}")

        message = Defaults.GET_CLIENT_PUBLIC_KEY + self.id +\
            serialize_integer(self.get_v())

        log.info(f"Sending \'{message}\'to a server")

        self.sock.sendall(message)

        log.info("Receiving public key from server")

        self.key = deserialize_integer(self.recv_from_server())
        log.info(f"My public key {self.key}")

        log.info("Check correctness of public key")

        if (pow(self.key, self.e, self.n) + name_to_integer(self.name)) % self.n != self.get_v():
            log.error("Incorrect public key")
            log.error(f"p^e: {pow(self.key, self.e, self.n)}")
            log.error(f"v: {self.get_v()}")
            log.error(f"i: {name_to_integer(self.name)}")
            log.error(f"n: {self.n}")
        else:
            log.info("Public key is correct")

    def run(self,
            initiator,
            opponent_port,
            srv_port=Defaults.Port,
            opponent_addr=Defaults.Addr,
            srv_addr=Defaults.Addr
            ):

        self.connect_to_server(srv_addr, srv_port)
        log.info("Closing connection with server")
        self.sock.shutdown()
        self.sock.close()

        self.sock = None
        log.info("Establishing connection with opponent")
        if initiator:
            self.connect_to_opponent(opponent_addr, opponent_port)
        else:
            self.wait_for_opponent()

    def fetch_parameters_from_server(self):
        message = Defaults.GET_PARAMETERS
        self.sock.sendall(message)

        data = self.recv_from_server()
        pdebug(f"Received raw parametes {data}")
        data = data.split(b'\x00'*5)

        self.n = deserialize_integer(data[0])
        self.e = deserialize_integer(data[1])
        self.g = deserialize_integer(data[2])

    def get_v(self):
        return pow(self.g, -self.secret, self.n)

    def connect_to_opponent(self, addr, port):
        log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.info("Connecting to opponent")
        self.sock.connect((addr, port))
        log.info("Connected to opponent")

    def wait_for_opponent(self):
        pass


if __name__ == "__main__":
    server = Server()
    client = Client('Alice')
