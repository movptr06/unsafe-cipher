#!/usr/bin/env python3

from Crypto.Util.number import getPrime, isPrime

X = 2 ** 2000

while True:
    Y = getPrime(48)
    P = X * Y
    if isPrime(P + 1):
        P += 1
        break

print("P =", P)

h1 = (P - 1) // 2
h2 = (P - 1) // Y

for y in range(2, P - 1):
    if pow(y, h1, P) != 1 and pow(y, h2, P) != 1:
        G = y
        break

print("G =", G)
