#!/usr/bin/env python
# -*- coding: utf-8 -*-

from timelock import TimeLockServer
from timelock import TimeLockClient
from timelock import TimeLockUser
import time
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

from Crypto.Protocol.SecretSharing import Shamir

def create_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(message_key, plaintext, associated_data):
    aesgcm = AESGCM(message_key)
    # TODO: decide what i want to use for a nonce
    serializedPlaintext = bytes(pickle.dumps(plaintext).hex(), 'ascii')
    ciphertext = aesgcm.encrypt(b'0101010', serializedPlaintext, associated_data)
    return ciphertext

def derive_key(ck):
    h = hmac.HMAC(ck, hashes.SHA256(), backend=default_backend())
    h.update(bytes(0x01))
    key = h.finalize()
    return key

def sign_time(priv, time):
    return priv.sign(time,ec.ECDSA(hashes.SHA256()))

def setup():
    priv, pub = create_keys()
    key = derive_key(b'key')
    plaintext = 'secret data'

    # contents = encrypt(key, plaintext, None)

    time_interval = 60
    valid_answer = 0
    start = 0
    t = TimeLockServer(plaintext, pub, time_interval, start, valid_answer)
    return t, priv

def split_secret(contents):
    shares = Shamir.split(2, 3, contents)


plaintext = 'secret data'
t = 60
c = TimeLockClient(plaintext, t)

#import pdb; pdb.set_trace()
c.register(5)

print(c.servers)
for server in c.servers:
    pass
c.check_in()
print("------------")
for server in c.servers:
    pass
user = TimeLockUser(c.servers)
user.request_start()
user.solved = c.aes
user.present_solved()
#import pdb; pdb.set_trace()
user.combine()
plaintext = user.decrypt()
if plaintext != "secret data":
    print("did not decrypt successfully")
"""
serialized = bytes(pickle.dumps(time.time()).hex(), 'ascii')
signed = sign_time(priv, serialized)
t.check_in(signed, serialized)
start = t.request_start()
print(start)
"""
