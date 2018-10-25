import collections
import socket
import select
import sys
import re
from logging import info as log_info
import datetime
from time import time

# from messages_pb2 import ChatRequest, ChatResponse
from protocol import recv_until_end_messages, send_message
import psycopg2

import json
from collections import namedtuple

from umbral.config import set_default_curve
from umbral import keys, signing, pre

import pickle


# collections.namedtuple('Client', 'sock addr')
class Client(object):
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.id = None
        self.pub_key = None

    def _set_pub_key(self, data):
        self.pub_key = self._get_pub_key(data)

    def __str__(self):
        return "Client({})".format(self.addr)

    def _get_pub_key(self, data):
        return keys.UmbralPublicKey.from_bytes(data)



class Server(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connected_clients = []
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # TODO
        set_default_curve()
        self.alices_private_key = keys.UmbralPrivateKey.from_bytes(
            b'\x86(\xb4Av\xa7\xf8\x1a\x16\x08\xc0K3\xa8\x1a;"i\xa8\x13Q\xc4s\xe5\x19\xef\x86@\x011\xf7\xfd')
        self.alices_public_key = keys.UmbralPublicKey.from_bytes(
            b'\x03\xb6\x81\xba\x8e\xcb\x08e\x7f(\x04\xe3\xff\xbe\xc6UA\xa0\xfe5\x1c\xb2\xe0\xf0\xf7;\xd1D}NHo\xf7')

        self.alices_signing_key = keys.UmbralPrivateKey.from_bytes(
            b'Q:5|\x01^=\xd6D\xbd\xed\xbb\x8f\xef\xc9\x04\xed2g}\xf3Yn\xf4\xb2\xfdZ\x03\x16\xceM\x94')
        self.alices_verifying_key = keys.UmbralPublicKey.from_bytes(
            b'\x03Yn\x9dx\xa7\x1c\xd1\xad\xe5\x80\xc9[\xe8^\xae\x81\x95\xaaQ\xadi\x9d\x83\x91\x18}\xc2\x85\xe3\x1em\xd0')
        self.alices_signer = signing.Signer(private_key=self.alices_signing_key)

        try:
            self._db_connect()
        except BaseException:
            log_info("Unable to connect database")

    def _db_connect(self):
        self.db = psycopg2.connect(
            "dbname='nucypher' user='postgres' host='localhost' password='***'")
        log_info("Connected to {dbname} as {user}, host: {host}".format(
            dbname='chat_db',
            user='postgres',
            host='localhost'
        ))

    def _register_client(self, client):
        self.connected_clients.append(client)

    def _unregister_and_close_client(self, client):
        # if client.id is not None:
        # TODO old fn
        # self._logout_user(client)
        self.connected_clients.remove(client)
        client.sock.close()

    def _get_client_by_sock(self, sock):
        clients = list(
            filter(
                lambda x: x.sock == sock,
                self.connected_clients))
        assert len(clients) == 1
        return clients[0]

    def _send_message_to_client(self, client, message):
        # TODO old fn
        data = pickle.dumps(message)
        send_message(client.sock, data)
        log_info("sended {len} bytes to {client}: {data}".format(
            len=len(message),
            client=client,
            data=message
        ))

    def _input_loop(self):
        while True:
            socks_to_read = list(map(lambda x: x.sock, self.connected_clients))

            # Linux epoll magic
            socks_ready_to_read, _, _ = select.select(
                [self.server_sock] + socks_to_read, [], [])

            for sock in socks_ready_to_read:
                if sock == self.server_sock:
                    sock, addr = self.server_sock.accept()
                    new_client = Client(sock=sock, addr=addr)
                    self._register_client(new_client)

                    log_info("{} connected".format(str(new_client)))

                    # TODO clear
                    #data = namedtuple('Point', ['custom_user_id'])

                    #self._client(new_client, data.custom_user_id)
                    #count = count + 1
                    #data.custom_user_id = count

                else:
                    client = self._get_client_by_sock(sock)
                    data = recv_until_end_messages(client.sock)
                    if not data:
                        self._unregister_and_close_client(client)
                        log_info(
                            "{} is offline (initiated by the client)".format(
                                str(client)))
                        continue

                    log_info(
                        "received {len} bytes from {client}: {data}".format(
                            len=len(data), client=client, data=data))

                    #data = pickle.loads(data)
                    data = self._parse_json(data)
                    if "custom_user_id" in data.keys():
                        client._set_pub_key(data.pub_key)
                        self._client(client, data.custom_user_id)
                    else:
                        self._manager(data)

    # Manager
    def _manager(self, data):
        eth_address = data.ids
        if "discount" in data.keys():
            discount = data.data

            #offer_custom_id = self.get_offer_custom_id(discount)
            offer_custom_id = 0
            self._add_offer_to_db(offer_custom_id)
            self._add_offers(eth_address, offer_custom_id)

            self.publish(self.encrypt(discount))
        else:
            for user in eth_address:
                if not self._is_user_in_db(user):
                    self._add_user_to_db(user)
                offer_custom_id = 0
                self._add_offer_for_user(user, offer_custom_id)

    # Bob
    def _client(self, client, custom_user_id):
        # for offer in self._get_offers_by_user(custom_user_id):
        # TODO (offer_cid, kfrags)
        # prepare data
        # self._send_message_to_client(client, data)

        #
        M, N = 10, 20
        kfrags = pre.generate_kfrags(delegating_privkey=self.alices_private_key,
                                     receiving_pubkey=client.pub_key,
                                     signer=self.alices_signer,
                                     threshold=M,
                                     N=N)
        #while True:
        b_kfrags=[]
        for kf in kfrags:
            b_kfrags.append(kf.to_bytes())
        self._send_message_to_client(client, b_kfrags)

    def encrypt(self, data):
        return pre.encrypt(self.alices_public_key, data)

    def publish(self, ciphertext, capsule):
        # TODO
        # NOW IT IS BUMP
        f = open('./blockchain', 'wb')
        pickle.dump([ciphertext, capsule.to_bytes()], f)
        f.close()

        return ciphertext, capsule

    def get_offer_custom_id(self, text):
        # TODO
        return 0

    def _parse_json(self, data):
        data = json.loads(data, object_hook=lambda d: namedtuple('X', d.keys())(*d.values()))
        log_info("parsed offer for {clients}".format(clients=data.ids))
        return data

    def _add_offers(self, users, offer_id):
        for user in users:
            if not self._is_user_in_db(user):
                self._add_user_to_db(user)
            self._add_offer_for_user(user, offer_id)

    def _add_offer_to_db(self, offer_cid):
        cursor = self.db.cursor()
        cursor.execute("INSERT INTO offers (data) "
                       "VALUES (%s) RETURNING id;",
                       (offer_cid,))
        id = cursor.fetchone()[0]
        self.db.commit()
        return id

    def _is_user_in_db(self, user_id):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM users WHERE custom_id = %s;", (user_id,))
        rows = cursor.fetchall()

        return bool(len(rows))

    def _is_access_to_offer(self, user_cid, offer_cid):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM users WHERE custom_id = %s AND %s = ANY(offers);", (user_cid, offer_cid,))
        rows = cursor.fetchall()

        return bool(len(rows))

    def _get_offers_by_user(self, user_cid):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM users WHERE custom_id = %s;", (user_cid,))
        rows = cursor.fetchall()

        return rows

    def _add_user_to_db(self, user_id):
        cursor = self.db.cursor()
        cursor.execute("INSERT INTO users (custom_id) "
                       "VALUES (%s);",
                       (user_id,))
        self.db.commit()

    # UPDATE users SET topics = topics || '{cats,mice}';
    def _add_offer_for_user(self, user_cid, offer_cid):
        cursor = self.db.cursor()
        cursor.execute("UPDATE users "
                       "SET offers = offers || {%s} "
                       "WHERE custom_id = %s;",
                       (offer_cid, user_cid,))
        self.db.commit()
        return True

    def start(self):
        # TODO clear
        s, c = self.encrypt(b"discount25")
        self.publish(s, c)

        self.server_sock.bind((self.host, self.port))
        log_info("Server started")
        self.server_sock.listen(10)
        try:
            self._input_loop()
        finally:
            self.server_sock.close()


def main():
    import logging
    logging.basicConfig(level=logging.DEBUG)

    Server(host='0.0.0.0', port=8078).start()


if __name__ == "__main__":
    main()
