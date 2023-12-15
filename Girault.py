import Defaults
from Logger import Logger
import Utils
# import MyCrypto
# from Crypto.PublicKey import RSA
# from pygroup.groups import Group

from pathlib import Path
import socket
import threading
import random

pdebug = Defaults.pdebug


class Server():
    def __init__(self, addr=Defaults.Addr, port=Defaults.Port):
        self.log = Logger(Defaults.LogPath)
        self.log.AddPostfix('[Server]')

        # self.rsa_provider = MyCrypto.RSA(bitlen=16)
        # (self.e, self.d, self.p, self.q, self.n) = self.rsa_provider.generate_keys()
        # self.g = self.find_group_generator(self.n)

        self.p = 919
        self.q = 839
        self.n = 771041
        self.e = 53
        self.d = 420929
        self.g = 77
        self.clients_pub_keys = {}

        pdebug(f" e = {self.e}")
        pdebug(f" d = {self.d}")
        pdebug(f" n = {self.n}")
        pdebug(f" g = {self.g}")

        self.log.info("Ready to publish")
        self.log.info(f"n = {self.n}")
        self.log.info(f"e = {self.e}")
        self.log.info(f"g = {self.g}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((addr, port))
        self.log.info(f"Server binded to {addr}:{port}")
        self.sock.listen()

        self.serve_forever()

    # def find_group_generator(self, n):
    #     G = Group('mult', n)
    #     g = G.g()
    #     go = G.go()
    #     overall = list(zip(g, go))
    #     return max(overall, key=lambda pair: pair[1])[0]

    def serve_forever(self):
        while True:
            conn, client_addr = self.sock.accept()
            self.log.info(f"Established connection with {client_addr}")
            threading.Thread(target=self.handle_client,
                             args=(conn, client_addr)).start()

    def handle_client(self, conn, client_addr):
        while True:
            data = None
            while not data:
                data = conn.recv(Defaults.MESSAGE_LENGTH)

            # Send client's public key after authentication
            if data[:Defaults.MSG_CODE_LENGTH] == Defaults.GET_CLIENT_PUBLIC_KEY:
                self.log.info("Get message code: GET_CLIENT_PUBLIC_KEY")
                self.send_client_public_key(conn,
                                            data[Defaults.MSG_CODE_LENGTH:])

            if data[:Defaults.MSG_CODE_LENGTH] == Defaults.GET_PARAMETERS:
                self.send_client_parameters(conn)

    def authenticate_client(self, client_id):
        pass

    def generate_client_pub_key(self, client_id, v):
        pdebug(f"Generating pub key for {Utils.deserialize_name(client_id)}")
        i = Utils.deserialize_name_to_int(client_id)
        pdebug(f"i = {i}")
        pdebug(f"v = {v}")
        P = pow((v - i), self.d, self.n)
        pdebug(f"P = {P}")
        self.clients_pub_keys[client_id] = P

    def send_client_public_key(self, conn, data):
        client_id = data[:Defaults.ID_LENGTH]
        client_name = Utils.deserialize_name(client_id)
        v = Utils.deserialize_integer(data[Defaults.ID_LENGTH:])

        self.log.info(f"Client id: {client_name}")
        self.log.info("Authenticating client")
        self.authenticate_client(client_id)

        if client_id not in self.clients_pub_keys:
            self.log.info("Generating client's public key")
            self.generate_client_pub_key(client_id, v)
            self.log.info(f"Generated for client {client_name}"
                          f" public key: {self.clients_pub_keys[client_id]}")

        self.log.info("Sending client's public key")
        key = self.clients_pub_keys[client_id]
        key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='little')
        conn.sendall(key)

    def send_client_parameters(self, conn):
        n = Utils.serialize_integer(self.n)
        e = Utils.serialize_integer(self.e)
        g = Utils.serialize_integer(self.g)

        conn.sendall(n + Defaults.DATA_SEP + e + Defaults.DATA_SEP + g)


class Client():
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret
        self.log = Logger(Defaults.LogPath)
        self.log.AddPostfix(f"[Client:{name}]")

    def recv_from_sock(self, sock):
        data = None
        while not data:
            data = sock.recv(Defaults.MESSAGE_LENGTH)
        return data

    def connect_to_server(self, addr, port):
        self.log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log.info("Connecting to a server")

        try:
            self.sock.connect((addr, port))
        except socket.error as e:
            self.log.error(f"Failed to establish connection with opponent "
                           f" {addr}:{port}: {e} [probably remote is down]")
            return

        self.log.info("Connected to a server")

        self.log.info("Getting scheme parameters")
        self.fetch_parameters_from_server()
        self.log.info("Fetched parameters from server")

        self.log.info(f"n: {self.n}")
        self.log.info(f"e: {self.e}")
        self.log.info(f"g: {self.g}")

        message = Defaults.GET_CLIENT_PUBLIC_KEY + Utils.serialize_name(self.name) +\
            Utils.serialize_integer(self.get_v())

        pdebug(f"Sending \'{message}\'to a server")

        self.sock.sendall(message)

        self.log.info("Receiving public key from server")

        self.key = Utils.deserialize_integer(self.recv_from_sock(self.sock))
        self.log.info(f"My public key {self.key}")

        self.log.info("Checking correctness of public key...")

        if (pow(self.key, self.e, self.n) +
                Utils.name_to_integer(self.name) % self.n) % self.n != self.get_v():
            self.log.error("Incorrect public key")
            self.log.error(f"p: {self.key}")
            self.log.error(f"p^e: {pow(self.key, self.e, self.n)}")
            self.log.error(f"v: {self.get_v()}")
            self.log.error(f"i: {Utils.name_to_integer(self.name)}")
            self.log.error(f"n: {self.n}")
            exit()
        else:
            self.log.info("Public key is correct")

        self.sock.close()
        self.sock = None

    def cli(self):
        while True:
            print("\nChoose an action:")
            print("1. Import keys")
            print("2. Export keys")
            print("3. Connect to server")
            print("4. Establish a secret key with other client")
            print("5. Wait for a secret key establishing")
            print("6. Authenticate to an opponent")
            print("7. Authenticate opponent")
            print("8. Exit")
            print("\n> ", end='')

            choice = int(input())

            print()

            if choice == 1:
                print("Do you want to use dafault key files? [Y/n]: ", end='')
                choice = input()

                pub_key_filename = f"{self.name}_{Defaults.PUB_KEY_PATH}"
                session_key_filename = f"{self.name}_{Defaults.SESSION_KEY_PATH}"

                if choice == 'n':
                    print("Enter private key filename: ", end='')
                    session_key_filename = input()

                    print("Enter public key filename: ", end='')
                    pub_key_filename = input()

                self.import_keys(pub_key_filename, session_key_filename)

            elif choice == 2:
                print("Do you want to use default key files? [Y/n]: ", end='')
                choice = input()

                pub_key_filename = f"{self.name}_{Defaults.PUB_KEY_PATH}"
                session_key_filename = f"{self.name}_{Defaults.SESSION_KEY_PATH}"

                if choice == 'n':
                    print("Enter private key filename: ", end='')
                    session_key_filename = input()

                    print("Enter public key filename: ", end='')
                    pub_key_filename = input()

                self.export_keys(pub_key_filename, session_key_filename)

            elif choice == 3:
                print("Do you want to use default localhost server? [Y/n]: ",
                      end='')
                choice = input()

                if choice == 'n':
                    print("Enter server's address and port (addr port)")
                    addr_port_split = input('> ').split(' ')

                    addr = addr_port_split[0]
                    port = int(addr_port_split[1])
                else:
                    addr = Defaults.Addr
                    port = Defaults.Port

                self.connect_to_server(addr, port)
            elif choice == 4:
                print("Enter yout opponent's addr and port (addr port)")
                prefix = input('> ').split(' ')
                opponent_addr = prefix[0]
                opponent_port = int(prefix[1])

                self.connect_to_opponent_and_generate_key(opponent_addr,
                                                          opponent_port)

                print("Secret key is established!")
            elif choice == 5:
                print("Enter your socket port: ", end='')
                port = int(input())
                self.wait_for_opponent(Defaults.Addr, port)
            elif choice == 6:
                print("Enter yout opponent's addr and port (addr port)")
                prefix = input('> ').split(' ')
                opponent_addr = prefix[0]
                opponent_port = int(prefix[1])
                self.authenticate_to_opponent(opponent_addr, opponent_port)

            elif choice == 7:
                print("Enter your socket port: ", end='')
                port = int(input())
                self.authenticate_opponent(Defaults.Addr, port)

            elif choice == 8:
                print("Bye!")
                return

            else:
                print("\rWrong option\r", end='')

    def authenticate_to_opponent(self, addr, port):
        self.log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log.info("Connecting to opponent")
        try:
            self.sock.connect((addr, port))
        except socket.error as e:
            self.log.error(f"Failed to establish connection with opponent "
                           f" {addr}:{port}: {e} [probably remote is down]")

        self.log.info("Connected to opponent")

        r_a = random.getrandbits(220)
        t = pow(self.g, r_a, self.n)

        self.log.info("Sending id, public key and t to opponent")
        message = Utils.serialize_integer(Utils.name_to_integer(self.name)) +\
            Defaults.DATA_SEP + Utils.serialize_integer(self.key) +\
            Defaults.DATA_SEP + Utils.serialize_integer(t)

        self.sock.sendall(message)

        self.log.info("Waiting for answer")
        data = self.recv_from_sock(self.sock)
        r_b = Utils.deserialize_integer(data)
        self.log.info(f"Got R from opponent: {data}")

        y = r_a + self.secret * r_b

        message = Utils.serialize_integer(y)
        self.sock.sendall(message)

        data = self.recv_from_sock(self.sock)
        data = Utils.deserialize_integer(data)

        if data == 1:
            self.log.info("Authentication success!")
            print("Authentication success!")
        else:
            self.log.error("Authentication failure!")
            print("Authentication failure!")

        self.sock.close()
        self.sock = None

    def authenticate_opponent(self, addr, port):
        self.log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((addr, port))
        self.log.info(f"Socket binded to {addr}:{port}")
        self.sock.listen()

        self.log.info("Waiting for incomming connection")
        conn, client_addr = self.sock.accept()
        self.log.info(f"Established connection with {client_addr}")

        r = random.getrandbits(30)

        data = self.recv_from_sock(conn)
        data = data.split(Defaults.DATA_SEP)
        i = Utils.deserialize_integer(data[0])
        p = Utils.deserialize_integer(data[1])
        t = Utils.deserialize_integer(data[2])

        message = Utils.serialize_integer(r)
        conn.sendall(message)

        data = self.recv_from_sock(conn)
        y = Utils.deserialize_integer(data)

        v = (pow(p, self.e, self.n) + i % self.n) % self.n

        res = t == pow(self.g, y, self.n) * pow(v, r, self.n) % self.n

        conn.sendall(Utils.serialize_integer(res))
        self.sock.close()
        self.sock = None

    def import_pub_key(self, path):
        file = open(path, "r")
        self.key = int(file.read().split('=')[1])
        file.close()

    def import_sess_key(self, path):
        file = open(path, "r")
        self.session_key = int(file.read().split('=')[1])
        file.close()

    def import_keys(self, pub_key, sess_key):
        pub_key = Path(pub_key)
        sess_key = Path(sess_key)

        if pub_key.is_file() and sess_key.is_file():
            self.log.info(f"Importing keys from {pub_key} [pub-key] and "
                          f"{sess_key} [session-key]")
            self.import_pub_key(pub_key)
            self.import_sess_key(sess_key)
            self.log.info("Success!")
            self.log.info(f"Public key: {self.key}")
            self.log.info(f"Session key: {self.session_key}")
        else:
            self.log.error("Files do not exist!")
            return

    def export_pub_key(self, path):
        try:
            with open(path, 'w') as f:
                f.write(f"P={self.key}")
        except AttributeError:
            self.log.warn("No public key to export")

    def export_sess_key(self, path):
        try:
            with open(path, 'w') as f:
                f.write(f"Session key={self.session_key}")
        except AttributeError:
            self.log.warn("No session key to export")

    def export_keys(self, pub_key, sess_key):
        pub_key = Path(pub_key)
        sess_key = Path(sess_key)

        self.log.info(f"Exporting keys to {pub_key} [pub-key] and "
                      f"{sess_key} [session-key]")

        self.export_pub_key(pub_key)
        self.export_sess_key(sess_key)
        self.log.info("Success!")

    def fetch_parameters_from_server(self):
        message = Defaults.GET_PARAMETERS
        self.sock.sendall(message)

        data = self.recv_from_sock(self.sock)
        pdebug(f"Received raw parametes {data}")
        data = data.split(Defaults.DATA_SEP)

        self.n = Utils.deserialize_integer(data[0])
        self.e = Utils.deserialize_integer(data[1])
        self.g = Utils.deserialize_integer(data[2])

    def get_v(self):
        return pow(self.g, -self.secret, self.n)

    def connect_to_opponent_and_generate_key(self, addr, port):
        self.log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log.info("Connecting to opponent")
        try:
            self.sock.connect((addr, port))
        except socket.error as e:
            self.log.error(f"Failed to establish connection with opponent "
                           f" {addr}:{port}: {e} [probably remote is down]")

        self.log.info("Connected to opponent")

        self.log.info("Sending public key and id to opponent")
        message = Utils.serialize_integer(self.key) + Defaults.DATA_SEP +\
            Utils.serialize_integer(Utils.name_to_integer(self.name))

        self.sock.sendall(message)

        self.log.info("Waiting for answer")
        data = self.recv_from_sock(self.sock)

        data = data.split(Defaults.DATA_SEP)
        opponents_key = Utils.deserialize_integer(data[0])
        opponents_id = Utils.deserialize_integer(data[1])

        self.log.info("Got opponent's parameters")
        self.log.info(f"Opponent's key: {opponents_key}")
        self.log.info(f"Opponent's key: {opponents_id}")

        self.session_key =\
            pow(pow(opponents_key, self.e, self.n) + opponents_id,
                self.secret, self.n)

        self.log.info(f"Generated session key {self.session_key}")

        self.sock.close()
        self.sock = None

    def wait_for_opponent(self, addr, port):
        self.log.info("Creating a socket")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((addr, port))
        self.log.info(f"Socket binded to {addr}:{port}")
        self.sock.listen()

        self.log.info("Waiting for incomming connection")
        conn, client_addr = self.sock.accept()
        self.log.info(f"Established connection with {client_addr}")

        self.log.info("Sending public key and id to opponent")
        message = Utils.serialize_integer(self.key) + Defaults.DATA_SEP +\
            Utils.serialize_integer(Utils.name_to_integer(self.name))

        conn.sendall(message)

        self.log.info("Waiting for answer")
        data = self.recv_from_sock(conn)

        data = data.split(Defaults.DATA_SEP)
        opponents_key = Utils.deserialize_integer(data[0])
        opponents_id = Utils.deserialize_integer(data[1])

        self.log.info("Got opponent's parameters")
        self.log.info(f"Opponent's key: {opponents_key}")
        self.log.info(f"Opponent's key: {opponents_id}")

        self.session_key =\
            pow(pow(opponents_key, self.e, self.n) + opponents_id,
                self.secret, self.n)

        self.log.info(f"Generated session key {self.session_key}")
        self.sock.close()
        self.sock = None
