#!/usr/bin/env python
# -*- coding: utf-8 -*-


from timelock import TimeLock
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

from main import encrypt
from main import derive_key
from main import sign_time
from main import create_keys
from main import setup



def test_setup():
    setup()
    print("setup successful")

def test_check_in():
    t, priv = setup()
    initial_start = t.request_start()
    if initial_start != 0:
        print("didn't get expected start")
        return None

    serialized = bytes(pickle.dumps(time.time()).hex(), 'ascii')
    signed = sign_time(priv, serialized)
    t.check_in(signed, serialized)
    new_start = t.request_start()
    if new_start != 1:
        print("didn't get expected start")
        return None
    print("check-in test successful")

def test_solve():
    t, priv = setup()
    contents = t.solve(1)
    if contents != None:
        print("unexpectedly accepted")
        return None
    contents = t.solve(0)
    if contents != 'secret data':
        print("unexpectedly failed")
        return None
    print("solve test successful")

test_setup()
test_check_in()
test_solve()


