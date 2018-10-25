import sys
import socket
import select

from protocol import send_message, recv_until_end_messages

from umbral import pre
from umbral import keys, signing
from umbral.config import set_default_curve


class Client(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        set_default_curve()
        self.bobs_private_key = keys.UmbralPrivateKey.from_bytes(
            b'"\xf7~\xb994\x1a\xe0b\x96.\'m\xa6<S\x06L\xb7\xb2\xf6a\x88^\xd3\xd6\xae!\xc7S^\xba')
        self.bobs_public_key = keys.UmbralPublicKey.from_bytes(
            b'\x03\xcfy\xd3\xbb\xf6\x9e\x9e\x82\xf6+c\xcar\xdc\xf2QaM\xc1\xf2h\xfdg\xdc\x16\xd0\xb4oA\xdc\x92\xdc')

    def _input_loop(self):
        # refactor this
        while True:
            print("listen")
            # Linux epoll magic
            inputs_ready_to_read, _, _ = select.select([self.server_socket, sys.stdin], [], [])

            for sock in inputs_ready_to_read:
                print("hello")
                if sock == self.server_socket:
                    data = recv_until_end_messages(sock)
                    print("hello")

                    if data:
                        offer_cid, kfrags = self._parse_response(data)
                        ciphertext, capsule = self.get_offer_from_blockchain(offer_cid)
                        self._get_raw_offer(ciphertext, capsule, kfrags)

                    else:
                        print("Disconnected from server")
                        sys.exit()
                else:
                    #data = sys.stdin.readline()[:-1]

                    #request = self._prepare_req()

                    #send_message(self.server_socket, request)
                    pass

    def _get_raw_offer(self, ciphertext, capsule, kfrags):
        cfrags = list()  # Bob's cfrag collection
        for kfrag in kfrags:
            cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
            cfrags.append(cfrag)  # Bob collects a cfrag

        for cfrag in cfrags:
            capsule.attach_cfrag(cfrag)

        bob_cleartext = pre.decrypt(ciphertext=ciphertext, capsule=capsule, decrypting_key=bobs_private_key)
        print(bob_cleartext)

    def get_offer_from_blockchain(self, offer_custon_id):
        # TODO
        # NOW IT IS BUMP
        f = open('./blockchain', 'rb')
        ciphertext = f.readline()
        capsule = f.readline()
        f.close()

        return ciphertext, capsule

    def _parse_response(self, data):
        # TODO
        return 0, data

    def _prepare_req(self):
        return ''

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
