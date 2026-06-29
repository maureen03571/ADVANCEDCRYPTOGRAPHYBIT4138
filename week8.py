#!/usr/bin/env python3
"""
Diffie-Hellman Key Exchange Demonstration
Week 8 - BIT4138 Advanced Cryptography
"""

import random

def diffie_hellman(p, g, a_private=None, b_private=None):
    if a_private is None:
        a_private = random.randint(2, p-2)
    if b_private is None:
        b_private = random.randint(2, p-2)

    A = pow(g, a_private, p)
    B = pow(g, b_private, p)

    S_alice = pow(B, a_private, p)
    S_bob = pow(A, b_private, p)

    return {
        'p': p,
        'g': g,
        'a': a_private,
        'b': b_private,
        'A': A,
        'B': B,
        'S_alice': S_alice,
        'S_bob': S_bob
    }

def diffie_hellman_large():
    print("\n" + "=" * 50)
    print("Diffie-Hellman with Large 2048-bit Prime")
    print("=" * 50)
    
    # 2048-bit prime from RFC 3526 (Group 14)
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
    g = 2
    
    # Generate random private keys
    a_private = random.randint(2, p-2)
    b_private = random.randint(2, p-2)
    
    result = diffie_hellman(p, g, a_private, b_private)
    
    print(f"Prime size: {p.bit_length()} bits")
    print(f"Generator: {g}")
    print()
    print(f"Alice private (hex): {hex(result['a'])[:30]}...")
    print(f"Bob private (hex): {hex(result['b'])[:30]}...")
    print()
    print(f"Alice public (hex): {hex(result['A'])[:30]}...")
    print(f"Bob public (hex): {hex(result['B'])[:30]}...")
    print()
    print(f"Shared secret (hex): {hex(result['S_alice'])[:30]}...")
    
    if result['S_alice'] == result['S_bob']:
        print("✅ SUCCESS: Both parties have the same shared secret!")
    else:
        print("❌ ERROR: Secrets do not match!")

def main():
    print("=== Diffie-Hellman Key Exchange ===")
    print("Small Prime Example (p=23, g=5)")
    print("-" * 40)
    
    p = 23
    g = 5
    a = 6
    b = 15
    
    result = diffie_hellman(p, g, a, b)
    
    print(f"Public parameters:")
    print(f"  Prime (p): {result['p']}")
    print(f"  Generator (g): {result['g']}")
    print()
    print(f"Private keys:")
    print(f"  Alice: {result['a']}")
    print(f"  Bob: {result['b']}")
    print()
    print(f"Public keys (exchanged):")
    print(f"  Alice sends: {result['A']}")
    print(f"  Bob sends: {result['B']}")
    print()
    print(f"Shared secret (computed independently):")
    print(f"  Alice computes: {result['S_alice']}")
    print(f"  Bob computes: {result['S_bob']}")
    print()
    
    if result['S_alice'] == result['S_bob']:
        print("✅ SUCCESS: Both parties have the same shared secret!")
        print(f"✅ Shared Secret: {result['S_alice']}")
    else:
        print("❌ ERROR: Secrets do not match!")
    
    # Run large prime example
    diffie_hellman_large()

if __name__ == "__main__":
    main()