
# RSA Fermat Attack

Based on [this](https://www.youtube.com/watch?v=-ShwJqAalOk) video by Computerphile. Just saw it and decided to implement it.

## Requirements:
1. Python 3.8 or higher
2. `python3 -m pip install -r requirements.txt`

## PoC Usage:

1. Generate a vulnerable public key using `./genWeakPrimeRsaKey.py -p vulnerable.pem`
2. Run the attack on the public key using `./rsaFermatAttack.py vulnerable.pem -o cracked.pem`
3. Test if the keys are related `./checkRsaKeysRelated.py cracked.pem vulnerable.pem`

## Attack Details
This attack exploits cases where the 2 picked primes for the RSA private key generation, P and Q, are too close together. Any decent cryptographic tool or library makes sure this isn't the case.

So, starting at the square root of N (N = P * Q) we increment and test the values. After deriving
P and Q the private key value D is calculated by getting the euler totient of P and Q and getting
the inverse modulo of the exponent e and said euler totient.

Note I am not cryptographer, the video explains the process alot better