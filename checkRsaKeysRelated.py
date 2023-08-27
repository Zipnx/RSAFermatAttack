#!/usr/bin/python3

import sys, os

from binascii import hexlify

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Too lazy to add color
def good(s): print(f'[+] {s}')
def info(s): print(f'[*] {s}')
def error(s): print(f'[!] {s}')

def signMessage(privKey: RSA.RsaKey, message: bytes) -> bytes:
    
    hashObj = SHA256.new(message)

    return pkcs1_15.new(privKey).sign(hashObj)

def verifyMessage(pubKey: RSA.RsaKey, message: bytes, signature: bytes) -> bool:

    hashObj = SHA256.new(message)

    try:
        pkcs1_15.new(pubKey).verify(hashObj, signature)
    except (ValueError, TypeError):
        return False
    
    return True

def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <PRIV> <PUB>')
        return

    with open(sys.argv[1], 'rb') as f:
        priv = RSA.import_key(f.read())


    with open(sys.argv[2], 'rb') as f:
        pub = RSA.import_key(f.read())
    
    msg = os.urandom(69*420)

    signature = signMessage(priv, msg)

    info(f'Signature: {hexlify(signature).decode()}')

    res = verifyMessage(pub, msg, signature)

    if res:
        good('Keys match!')
    else:
        error('Non-Matching key pair')


if __name__ == '__main__': main()
