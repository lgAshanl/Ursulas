import sys
import socket
import select

from protocol import send_message, recv_until_end_messages

from collections import namedtuple

from umbral import pre
from umbral import keys, signing
from umbral.config import set_default_curve
from umbral.curve import Curve
from umbral.params import UmbralParameters

import pickle

import json
import pandas as pd

import codecs

class Client(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        set_default_curve()
        self.bobs_private_key = keys.UmbralPrivateKey.gen_key()
        self.bobs_public_key = self.bobs_private_key.get_pubkey()
        #self.bobs_private_key = keys.UmbralPrivateKey.from_bytes(
        #    b'"\xf7~\xb994\x1a\xe0b\x96.\'m\xa6<S\x06L\xb7\xb2\xf6a\x88^\xd3\xd6\xae!\xc7S^\xba')
        #self.bobs_public_key = keys.UmbralPublicKey.from_bytes(
        #    b'\x03\xcfy\xd3\xbb\xf6\x9e\x9e\x82\xf6+c\xcar\xdc\xf2QaM\xc1\xf2h\xfdg\xdc\x16\xd0\xb4oA\xdc\x92\xdc')

        self.alices_public_key = keys.UmbralPublicKey.from_bytes(
            b'\x03\xb6\x81\xba\x8e\xcb\x08e\x7f(\x04\xe3\xff\xbe\xc6UA\xa0\xfe5\x1c\xb2\xe0\xf0\xf7;\xd1D}NHo\xf7')

        self.alices_verifying_key = keys.UmbralPublicKey.from_bytes(
            b'\x03Yn\x9dx\xa7\x1c\xd1\xad\xe5\x80\xc9[\xe8^\xae\x81\x95\xaaQ\xadi\x9d\x83\x91\x18}\xc2\x85\xe3\x1em\xd0')

    def _input_loop(self):
        # refactor this
        while True:
            # Linux epoll magic
            inputs_ready_to_read, _, _ = select.select([self.server_socket, sys.stdin], [], [])

            for sock in inputs_ready_to_read:
                if sock == self.server_socket:
                    data = recv_until_end_messages(sock)

                    if data:
                        offer_cid, kfrags = self._parse_response(data)
                        ciphertext, capsule = self.get_offer_from_blockchain(offer_cid)
                        self._get_raw_offer(ciphertext, capsule, kfrags)

                    else:
                        print("Disconnected from server")
                        sys.exit()
                else:
                    #data = sys.stdin.readline()[:-1]
                    pub_key = self.bobs_public_key.to_bytes()
                    eth_key = "~"

                    request = self._prepare_req(eth_key, pub_key)

                    send_message(self.server_socket, request)

    def _get_raw_offer(self, ciphertext, capsule, kfrags):
        capsule.set_correctness_keys(delegating=self.alices_public_key,
                                         receiving=self.bobs_public_key,
                                         verifying=self.alices_verifying_key)

        cfrags = list()  # Bob's cfrag collection
        for kfrag in kfrags:
            cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
            cfrags.append(cfrag)  # Bob collects a cfrag

        for cfrag in cfrags:
            capsule.attach_cfrag(cfrag)

        bob_cleartext = pre.decrypt(ciphertext=ciphertext, capsule=capsule, decrypting_key=self.bobs_private_key)
        print(capsule.to_bytes())
        print(bob_cleartext)

    def get_offer_from_blockchain(self, offer_custon_id):
        # TODO
        # NOW IT IS BUMP
        f = open('./blockchain', 'rb')
        data = pickle.load(f)
        ciphertext = data[0]
        capsule = pre.Capsule.from_bytes(data[1], UmbralParameters(Curve(714)))
        f.close()

        return ciphertext, capsule

    def _parse_response(self, data):
        # TODO
        data = pickle.loads(data)
        kfrags = []
        for bkf in data:
            kfrags.append(pre.KFrag.from_bytes(bkf))
        return 0, kfrags

    def _prepare_req(self, cui, pub_key):
        #pub_key = pickle.dumps(pub_key))
        #data = json.dumps([cui, pub_key])
        data = pickle.dumps([cui, pub_key])
        return data

    def start(self):
        self.server_socket.connect((self.host, self.port))
        try:
            self._input_loop()
        finally:
            self.server_socket.close()


def main():
    import logging
    logging.basicConfig(level=logging.DEBUG)

    Client(host='0.0.0.0', port=8078).start()


if __name__ == "__main__":
    main()
