#!/usr/bin/python3

# Zipnx - 26/08/2023 
# Its 3 am, i watched the Computerphile Video, i got nothing else to do with my life

import sys, math, argparse  

from os.path import isdir as isDirectory
from os.path import exists as fileExists

from Crypto.PublicKey import RSA

# I was too lazy to add color, i spedrun this script
def good(s): print(f'[+] {s}')
def info(s): print(f'[*] {s}')
def error(s): print(f'[!] {s}')

def phi(a, b):
    return (a - 1) * (b - 1)

# Newtons method, credz user448810 @StackOverflow
def isSquare(num: int) -> bool:
    
    x = num
    y = (x + 1) // 2

    while y < x:
        x = y
        y = (x + num // x) // 2

    return (x*x) == num

def constructKeyFromPrimes(p, q):
    e = 65537
    n = p * q

    d = pow(e, -1, phi(p, q))

    key = RSA.construct([n, e, d, p, q])

    return key

# This attack relies on the incorrect picking of P and Q, specifically, that they were picked close together
def attack(key: RSA.RsaKey, iters: int = 256):
    
    # Remember N = P * Q
    N = key.n

    # Ceil of integer square root of N
    a = math.isqrt(N) + 1
    b = None
    
    info('Starting attack...')
    for i in range(iters):
        
        
        b2 = a**2 - N
        
        if isSquare(b2):
            # The attack was successful and we can retrieve P and Q
            b = math.isqrt(b2)
            break
        
        a += 1

    if b is None:
        error('Attack failed.')
        return None  

    good('Attack successful!')
    
    #print(a, b)

    p = a + b
    q = a - b
    
    if N == p*q:
        good('Attack verified.')
    else:
        error('Attack verification failed.')
        return None

    #print(p)
    #print(q)

    return constructKeyFromPrimes(p, q)

def parseArgs():

    parser = argparse.ArgumentParser(description = 'Script that runs a Fermat attack against an RSA public key.')

    parser.add_argument('key', type = str, help = 'Public key file to use')
    parser.add_argument('-i', '--iterations', type = int, default = 256, help = 'Iterations to run (DEFAULT=256)')
    parser.add_argument('-o', '--output', type = str, help = 'Output file for the generated private key')

    return parser.parse_args()

def main():

    args = parseArgs()

    info(f'Using {args.iterations} iterations.')

    if not fileExists(args.key) or isDirectory(args.key):
        error('Invalid public key file')
        return
    
    
    publicKey = None

    with open(args.key, 'rb') as f:
        try:
            publicKey = RSA.importKey(f.read())
        except ValueError:
            error('File is not a valid RSA key format')
            return
    
    priv = attack(publicKey, args.iterations)
    
    if priv is None: return

    print()
    print(priv.export_key().decode())

    if args.output is not None:
        with open(args.output, 'wb') as f:
            f.write(priv.export_key())

if __name__ == '__main__':
    main()
