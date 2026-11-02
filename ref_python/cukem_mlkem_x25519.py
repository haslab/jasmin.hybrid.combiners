from os import urandom
from hashlib import sha3_256
from kyber_py.ml_kem import ML_KEM_768
import x25519
from Crypto.Hash import KMAC128

# Implementation of CuKEM+ (https://eprint.iacr.org/2025/1862) combining K-PKE of ML-KEM-768 and X25519

# kyber_py.ml_kem from https://github.com/GiacomoPope/kyber-py/tree/main
# x25519 from https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html#name-x25519py

# M for ML-KEM 
# X for X25519

# PRF f with key space {0, 1}^lambda -> {0, 1}^n
# Hash Function G: M -> R modelled as a RO
# Hash Function, KDF H: {0, 1}^* -> {0, 1}^n  modelled as a RO

# n will be 256

# Need for domain separation?

# s is the key to f

def G(m):
    return sha3_256(m).digest()

def H(m, k, c):
    return sha3_256(m + k + c).digest()

def f(k, data):
    return KMAC128.new(key=k, data=data, mac_len=32).digest()

def KeyGen():
    skX = urandom(32)

    pkX = x25519.X(skX, x25519.BASE)

    d = urandom(32)
    pkM, skM  = ML_KEM_768._k_pke_keygen(d)

    s = urandom(16) # lambda = 128?

    pk, sk = (pkX, pkM), (skX, skM, s, pkM) # added pkM to sk to be available in Decaps

    return sk, pk

def KeyGen_derand(coins):
    assert len(coins) == 80 # 32*2+16

    skX = coins[32:64]

    pkX = x25519.X(skX, x25519.BASE)

    d = coins[:32]
    pkM, skM  = ML_KEM_768._k_pke_keygen(d)

    s = coins[64:]

    pk, sk = (pkX, pkM), (skX, skM, s, pkM) # added pkM to sk to be available in Decaps

    return sk, pk


def Encaps(pk):
    (pkX, pkM) = pk
    
    m = urandom(32)
    r = G(m) # r needs to be 32 bytes according to FIPS 203

    cM = ML_KEM_768._k_pke_encrypt(pkM, m, r)

    ske = urandom(32)

    cX = x25519.X(ske, x25519.BASE) 
    ssX = x25519.X(ske, pkX)        

    c = (cM, cX) 

    ss = H(m, ssX, cX) 

    return ss, c

def Encaps_derand(pk, coins):
    assert len(coins) == 64 #32*2

    (pkX, pkM) = pk

    m = coins[:32]

    r = G(m) # r needs to be 32 bytes according to FIPS 203

    cM = ML_KEM_768._k_pke_encrypt(pkM, m, r)

    ske = coins[32:]

    cX = x25519.X(ske, x25519.BASE) 
    ssX = x25519.X(ske, pkX)        

    c = (cM, cX) 

    ss = H(m, ssX, cX) 

    return ss, c


def Decaps(sk, c):
    (skX, skM, s, pkM) = sk
    (cM, cX) = c

    m_ = ML_KEM_768._k_pke_decrypt(skM, cM)
    r_ = G(m_)

    if ML_KEM_768._k_pke_encrypt(pkM, m_, r_) != cM:
        return f(s, cM+cX) 

    ssX = x25519.X(skX, cX)

    ss = H(m_, ssX, cX)

    return ss


