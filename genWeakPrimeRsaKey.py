#!/usr/bin/python3

# Zipnx - 26/08/2023
# Generate test vulnerable 2048bit rsa keys, since there are not examples i could find

from Crypto.PublicKey import RSA

import sys, argparse
import sympy as sp
from typing import Tuple

# I mean, we are weak on purpose
import random

def good(s): print(f'[+] {s}')
def info(s): print(f'[*] {s}')
def error(s): print(f'[!] {s}')

def phi(a, b):
    return (a-1)*(b-1)


def pickWeakPrimes(primeDifference: int = 8) -> Tuple[int, int]:
    
    
    info('Picking random number...')

    # Pick the starting random number
    p = random.randint(2**1000, 2**1023)
    
    info('Picking prime for P...')

    # Make P be a prime
    while not sp.isprime(p): p += 1

    good('Prime found.')

    # Add a few primes in the range between
    cur = p + 1
    for i in range(max(primeDifference, 0)):
        
        while not sp.isprime(cur): cur += 1
        cur += 1

    info('Picking prime for Q...')
    # Now find the next prime, which is gonna be q

    q = p + 1

    while not sp.isprime(q): q += 1

    good('Done picking primes.')

    return p, q

def constructKeyFromPrimes(p, q) -> RSA.RsaKey:
    e = 65537
    n = p * q

    d = pow(e, -1, phi(p, q))
    
    key = RSA.construct([n, e, d, p, q])

    return key

def getArguments():
    parser = argparse.ArgumentParser(description = 'Script that generates weak RSA keys')
    parser.add_argument('-p', '--write-public', type = str, help = 'Write the public key to a specified file')
    parser.add_argument('-s', '--write-private', type = str, help = 'Write the private key to a specified file')
    parser.add_argument('-d', '--difference', type=int, default=8, help = 'The number of primes between the 2 picked ones.')

    return parser.parse_args()

def main():

    args = getArguments()

    p, q = pickWeakPrimes(primeDifference = args.difference if args.difference is not None else 8)

    privKey = constructKeyFromPrimes(p, q)
    pubKey = privKey.public_key()
    
    print(privKey.export_key().decode())
    print()
    print(pubKey.export_key().decode())

    if args.write_public is not None:
        with open(args.write_public, 'wb') as f:
            f.write(pubKey.export_key())

    if args.write_private is not None:
        with open(args.write_private, 'wb') as f:
            f.write(privKey.export_key())


if __name__ == '__main__':
    main()

