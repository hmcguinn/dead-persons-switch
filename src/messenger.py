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

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        serializedCert = bytes(pickle.dumps(cert).hex(), 'ascii')
        return self.server_signing_key.sign(serializedCert,ec.ECDSA(hashes.SHA256()))

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conn = {}
        self.certs = {}

        # TODO: verify this
        self.private_cert = None
    def generate_dh(self):
        private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generateCertificate(self):
        keys = self.generate_dh()
        serializedPublicKey = keys[1].public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        cert = {'name': self.name, 'public_key': serializedPublicKey}

        # TODO: where to store priv key?
        self.private_cert = {'private_key': keys[0], 'public_key': keys[1]}
        return cert

    def receiveCertificate(self, certificate, signature):
        try:
            serializedCert = bytes(pickle.dumps(certificate).hex(), 'ascii')
            self.server_signing_pk.verify(signature, serializedCert, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise
        public_key = serialization.load_pem_public_key(certificate['public_key'],backend=default_backend())

        # python does bad things with dicts in memory :(
        copiedCertificate = copy.deepcopy(certificate)
        copiedCertificate['public_key'] = public_key
        self.certs[certificate['name']] = copiedCertificate
        return

    def sendMessage(self, name, message):
        if name in self.conn:
            # send normally
            return self.conn[name]['ratchet'].ratchetEncrypt(message)
        else:
            # need to generate
            self.conn[name] = {}
            # TODO: generate this secret key
            secret_key = b'secret_key'
            self.conn[name]['ratchet'] = DoubleRatchet(secret_key, self.private_cert, self.certs[name]['public_key'], True)
            return self.conn[name]['ratchet'].ratchetEncrypt(message)

    def receiveMessage(self, name, header, ciphertext):
        if name in self.conn:
            # receive normally
            try:
                plaintext = self.conn[name]['ratchet'].ratchetDecrypt(header, ciphertext)
                return plaintext
            except Exception as e:
                return None
        else:
            # need to generate
            self.conn[name] = {}
            # TODO: generate this secret key
            secret_key = b'secret_key'
            self.conn[name]['ratchet'] = DoubleRatchet(secret_key, self.private_cert, self.certs[name]['public_key'], False)
            try:
                plaintext = self.conn[name]['ratchet'].ratchetDecrypt(header, ciphertext)
                return plaintext
            except Exception as e:
                return None


    def report(self, name, message):
        raise Exception("not implemented!")
        return


class DoubleRatchet:
    def __init__(self, secret_key=None, key_pair_sender=None, public_key_receiver=None, first_sender=True):
        self.MAX_SKIP = 50
        if first_sender:
            self.key_pair_sender = key_pair_sender
            self.key_pair_receiver = public_key_receiver
            self.root_key, self.chain_key_sender = self.kdf_root_key(secret_key, self.dh(self.key_pair_sender, self.key_pair_receiver))
            self.chain_key_receiver = None
            self.num_sent = self.num_received = self.num_prev_chain = 0
            self.mskipped = {}
        else:
            self.key_pair_sender = key_pair_sender
            self.key_pair_receiver = None
            self.root_key = secret_key
            self.chain_key_sender = self.chain_key_receiver = None
            self.num_sent = self.num_received = self.num_prev_chain = 0
            self.mskipped = {}



    def dh(self, dh_pair, dh_pub):
        shared_key = dh_pair['private_key'].exchange(ec.ECDH(), dh_pub)
        return shared_key

    def kdf_root_key(self, root_key, dh_out):
        info = b'kdf_root_key_HMAC_info'
        hkdf = HKDF(algorithm=hashes.SHA256(),
                          length=64,
                          info=info,
                          salt=root_key,
                          backend=default_backend())
        combined_keys = hkdf.derive(dh_out)
        root_key = combined_keys[:int(len(combined_keys)/2)]
        chain_key = combined_keys[int(len(combined_keys)/2):]
        return root_key, chain_key

    def kdf_ck(self, ck):
        h = hmac.HMAC(ck, hashes.SHA256(), backend=default_backend())
        h.update(bytes(0x01))
        h2 = h.copy()
        message_key = h.finalize()
        h2.update(bytes(0x02))
        chain_key = h2.finalize()
        return message_key, chain_key

    def encrypt(self, message_key, plaintext, associated_data):
        aesgcm = AESGCM(message_key)
        # TODO: decide what i want to use for a nonce
        serializedPlaintext = bytes(pickle.dumps(plaintext).hex(), 'ascii')
        ciphertext = aesgcm.encrypt(b'0101010', serializedPlaintext, associated_data)
        return ciphertext

    def decrypt(self, message_key, ciphertext, associated_data):
        try:
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(b'0101010', ciphertext, associated_data)
            hexPlaintext = ''.join(chr(x) for x in plaintext)
            parsedPlaintext = pickle.loads(bytearray.fromhex(hexPlaintext))
            return parsedPlaintext
        except Exception as e:
            return None

    def header(self, dh_pair, num_prev_chain, n):
        data = {}
        serializedPublicKey = dh_pair['public_key'].public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        data['public_key'] = serializedPublicKey
        data['num_prev_chain'] = num_prev_chain
        data['n'] = n
        serializedData = bytes(pickle.dumps(data).hex(), 'ascii')
        return serializedData

    def concat(self, ad, header):
        """
        data = {}
        if ad:
            data['ad'] = ad
        else:
            data['ad'] = len(header)

        data['header'] = header
        serializedData = bytes(pickle.dumps(data).hex(), 'ascii')
        """
        serializedData = bytes(pickle.dumps(header).hex(), 'ascii')
        #print(serializedData)
        return serializedData
        #return header

    def ratchetEncrypt(self, plaintext):
        self.chain_key_sender, message_key = self.kdf_ck(self.chain_key_sender)
        header = self.header(self.key_pair_sender, self.num_prev_chain, self.num_sent)
        self.num_sent += 1
        return self.concat(None, header), self.encrypt(message_key, plaintext, self.concat(None, header))
    def ratchetDecrypt(self, header, ciphertext):



        #print(id(header))
        hexHeader = ''.join(chr(x) for x in header)
        parsedHeader = pickle.loads(bytearray.fromhex(hexHeader))
        hexHeader = ''.join(chr(x) for x in parsedHeader)
        parsedHeader = pickle.loads(bytearray.fromhex(hexHeader))

        #plaintext = self.trySkippedMessageKeys(header, parsedHeader, ciphertext)
        #if plaintext != None:
        #    return plaintext
        #import pdb; pdb.set_trace()


        serializedPublicKey = None
        if self.key_pair_receiver:
            serializedPublicKey = self.key_pair_receiver.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if parsedHeader['public_key'] != serializedPublicKey:
            #self.skipMessageKeys(parsedHeader['num_prev_chain'])
            self.dhRatchet(parsedHeader)

        self.skipMessageKeys(parsedHeader['n'])
        self.chain_key_receiver, message_key = self.kdf_ck(self.chain_key_receiver)
        self.num_received += 1
        try:
            plaintext = self.decrypt(message_key, ciphertext, header)
            return plaintext
        except Exception as e:
            return None

    def generate_dh(self):
        private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())
        public_key = private_key.public_key()
        return {'private_key': private_key, 'public_key': public_key}

    def dhRatchet(self, header):
        self.num_prev_chain = self.num_sent
        self.num_sent = self.num_received = 0

        public_key = serialization.load_pem_public_key(header['public_key'],backend=default_backend())
        if self.key_pair_receiver:
            serializedPublicKey = self.key_pair_receiver.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_pair_receiver = public_key

        self.root_key, self.chain_key_receiver = self.kdf_root_key(self.root_key, self.dh(self.key_pair_sender, self.key_pair_receiver))
        self.key_pair_sender = self.generate_dh()
        self.root_key, self.chain_key_sender = self.kdf_root_key(self.root_key, self.dh(self.key_pair_sender, self.key_pair_receiver))

    def trySkippedMessageKeys(self, header, parsedHeader, ciphertext):
        if (parsedHeader['public_key'], parsedHeader['n']) in self.mskipped:
            message_key = self.mskipped[parsedHeader['public_key'], parsedHeader['n']]
            del self.mskipped[parsedHeader['public_key'], parsedHeader['n']]
            return self.decrypt(message_key, ciphertext, header)
        else:
            return None
    def skipMessageKeys(self, until):
        if self.num_received + self.MAX_SKIP < until:
            raise ValueError
        if self.chain_key_receiver != None:
            while self.num_received < until:
                self.chain_key_receiver, message_key = self.kdf_ck(self.chain_key_receiver)
                self.mskipped[(self.key_pair_receiver, self.num_received)] = message_key
                self.num_received += 1


