#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import subprocess
from cryptography.hazmat.primitives import padding
from collections import defaultdict
import os
import pickle
import string
import copy
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    def check_in(self, signature, serialized, new_valid, start, new_contents):
        try:
            #import pdb; pdb.set_trace()
            self.pub_key.verify(signature, serialized, ec.ECDSA(hashes.SHA256()))

            self.time = time.time() + self.time_increment

            # TODO: update start + valid answer
            self.current_start = start
            self.valid_answer = new_valid

            self.last_check_in = None
            self.contents = new_contents
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
        self.shares = defaultdict(list)

        self.split_contents(3,5)
        self.servers = None

    def create_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def update_aes_key(self):
        self.start = self.update_start()

    def re_encrypt(self):
        self.ct = self.encrypt_contents()
        self.split_contents(3,5)

    def encrypt_contents(self):
        aesgcm = AESGCM(self.aes)
        # TODO: decide what i want to use for a nonce
        serializedPlaintext = bytes(pickle.dumps(self.contents).hex(), 'ascii')
        ciphertext = aesgcm.encrypt(b'0101010', serializedPlaintext, None)
        return ciphertext

    def pad(self, m):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(m)
        padded = padded_data + padder.finalize()
        return padded

    def split_bytes(self, b):
        split = [b[i:i+16] for i in range(0, len(b), 16)]
        return split

    def split_contents(self, k, n):
        padded = self.pad(self.ct)

        split_data = self.split_bytes(padded)

        self.shares = defaultdict(list)
        for portion in split_data:
            share = Shamir.split(k, n, portion)
            for i, s in enumerate(share):
                self.shares[i].append(s)


        #shares = Shamir.split(k, n, ct)

    def register_servers(self, servers):
        self.servers = servers

    def sign_time(self, priv, time):
        return priv.sign(time,ec.ECDSA(hashes.SHA256()))

    def hash_key(self, key):
        digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(key)
        return digest.finalize()

    def update_start(self):
        seed = os.urandom(16)
        #import pdb; pdb.set_trace()
        hex_seed = seed.hex()

        command = "vdf-cli " + hex_seed + " 2048"
        #process = subprocess.Popen(command, shell=True)
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        vdf_output = result.stdout.strip()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=seed,iterations=390000,backend=default_backend())
        key = kdf.derive(vdf_output)

        self.aes = key

        # TODO: update start with VDF
        return seed

    def check_in(self):
        serialized = bytes(pickle.dumps(time.time()).hex(), 'ascii')
        signed = self.sign_time(self.priv, serialized)


        start = self.update_start()
        sha256 = self.hash_key(self.aes)
        self.re_encrypt()

        for i, server in enumerate(self.servers):
            server.check_in(signed, serialized, sha256, start, self.shares[i])

    def register(self, n):
        servers = []
        sha256 = self.hash_key(self.aes)
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
        self.ciphertext = None
        self.key = None

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
        command = "vdf-cli " + self.start.hex() + " 2048"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        vdf_output = result.stdout.strip()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=self.start,iterations=390000,backend=default_backend())
        key = kdf.derive(vdf_output)

        self.solved = self.hash_key(key)
        self.key = key

    def hash_key(self, key):
        digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(key)
        return digest.finalize()

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
        recombined = []
        for i in range(len(self.contents)):
            temp = []
            for j in range(len(self.contents[0])):
                temp.append(self.contents[j][i])
            plaintext = Shamir.combine(temp)
            recombined.append(plaintext)

        results =  b''.join(recombined)

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(results)
        parsed = data + unpadder.finalize()


        self.ciphertext = parsed
        print(parsed)
        return parsed

    def decrypt(self):
        try:
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(b'0101010', self.ciphertext, None)
            hexPlaintext = ''.join(chr(x) for x in plaintext)
            parsedPlaintext = pickle.loads(bytearray.fromhex(hexPlaintext))
            print(parsedPlaintext)
            return parsedPlaintext
        except Exception as e:
            print(e)
            return None


