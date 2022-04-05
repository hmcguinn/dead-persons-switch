#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from cryptography.hazmat.primitives import padding
import os
import pickle
import string
import copy
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import time
from Crypto.Protocol.SecretSharing import Shamir

# answer = H(key)
# start = VDF start 
# VDF end = key
# contents = secret shared
class TimeLockServer:
    def __init__(self, contents, public_key, t, start, valid_answer):
        self.contents = contents
        self.pub_key = public_key

        self.current_start = start
        self.valid_answer = valid_answer

        self.time_increment = t
        self.time = time.time() + self.time_increment

        self.last_check_in = time.time()

    def check_in(self, signature, serialized, new_valid, start):
        try:
            #import pdb; pdb.set_trace()
            self.pub_key.verify(signature, serialized, ec.ECDSA(hashes.SHA256()))

            self.time = time.time() + self.time_increment

            # TODO: update start + valid answer
            self.current_start = start
            self.valid_answer = new_valid

            self.last_check_in = None
        except Exception as e:
            raise

    def request_start(self):
        return self.current_start

    def solve(self, solved):
        if self.check_valid(solved):
              return self.contents
        return None

    def check_valid(self, answer):
        return answer == self.valid_answer

class TimeLockClient:
    def __init__(self, contents, t):
        priv, pub = self.create_keys()
        self.priv = priv
        self.pub = pub
        self.aes = None
        self.update_aes_key()
        self.contents = contents

        self.ct = self.encrypt_contents()

        self.time_interval = t
        self.shares = self.split_contents(3,5)
        self.servers = None
    
    def create_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def update_aes_key(self):
        self.aes = os.urandom(16)

    def re_encrypt(self):
        self.update_aes_key()
        self.ct = self.encrypt_contents()
        self.shares = self.split_contents(3,5)

    def encrypt_contents(self):
        aesgcm = AESGCM(self.aes)
        # TODO: decide what i want to use for a nonce
        serializedPlaintext = bytes(pickle.dumps(self.contents).hex(), 'ascii')
        ciphertext = aesgcm.encrypt(b'0101010', serializedPlaintext, None)
        return ciphertext


    def split_contents(self, k, n):
        ct = self.encrypt_contents()
        padder = padding.PKCS7(128).padder()
        serialized = bytes(pickle.dumps(self.contents).hex(), 'ascii')
        padded_data = padder.update(bytes(self.contents,'utf-8'))
        padded = padded_data + padder.finalize()


        #shares = Shamir.split(k, n, ct)
        shares = Shamir.split(k, n, padded)
        return shares

    def register_servers(self, servers):
        self.servers = servers

    def sign_time(self, priv, time):
        return priv.sign(time,ec.ECDSA(hashes.SHA256()))

    def hash_ct(self):
        digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(self.ct)
        return digest.finalize()

    def update_start(self):
        # TODO: update start with VDF
        return self.aes

    def check_in(self): 
        serialized = bytes(pickle.dumps(time.time()).hex(), 'ascii')
        signed = self.sign_time(self.priv, serialized)

        self.re_encrypt()

        sha256 = self.hash_ct()
        start = self.update_start()

        for server in self.servers:
            server.check_in(signed, serialized, sha256, start)

    def register(self, n):
        servers = []
        sha256 = self.hash_ct()
        for i in range(n):
            new_server = TimeLockServer(self.shares[i], self.pub, self.time_interval, self.aes, sha256)
            servers.append(new_server)

        self.register_servers(servers)

class TimeLockUser:
    def __init__(self, servers):
        self.servers = servers
        self.start = None
        self.contents = None
        self.solved = None

    def request_start(self):
        start_set = set()
        for server in self.servers:
            start_set.add(server.request_start())
        if len(start_set) > 1:
            print("error, bad server state")
            return None
        self.start = start_set.pop()
        return self.start

    def solve(self):
        pass

    def present_solved(self):
        contents = []
        for server in self.servers:
            share = server.solve(self.solved)
            if share == None:
                print("error in solving")
            else:
                contents.append(share)
        self.contents = contents

    def combine(self):
        plaintext = Shamir.combine(self.contents)
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(plaintext)
        parsedPlaintext = data + unpadder.finalize()


        print(parsedPlaintext)
        return parsedPlaintext

