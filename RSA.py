import sympy
import random

def generate_large_prime(bits=64):
    """
    Inputs:
        bits (int): The number of bits for the prime number.
    Output:
        int: A large prime number with the specified number of bits.
    Description:
        Generates a large prime number between 2^bits and 2^(bits+1).
    """
    return sympy.randprime(2**bits, 2**(bits+1))

def extended_gcd(a, b):
    """
    Inputs:
        a (int): The first integer.
        b (int): The second integer.
    Output:
        tuple: A tuple containing the gcd of a and b, and the coefficients x and y such that ax + by = gcd(a, b).
    Description:
        Computes the extended Euclidean algorithm to find the gcd of a and b and the coefficients x and y.
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1  # Update x coefficient
    y = x1  # Update y coefficient
    return gcd, x, y

def mod_inverse(e, phi):
    """
    Inputs:
        e (int): The exponent in the RSA algorithm.
        phi (int): Euler's totient function value of n (p-1)*(q-1).
    Output:
        int: The modular inverse of e modulo phi.
    Description:
        Calculates the modular inverse of e modulo phi using the extended Euclidean algorithm.
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')  # e must be coprime to phi
    else:
        return x % phi

def mod_exp(base, exp, mod):
    """
    Inputs:
        base (int): The base of the exponentiation.
        exp (int): The exponent.
        mod (int): The modulus.
    Output:
        int: The result of (base^exp) % mod using the method of repeated squaring.
    Description:
        Efficiently computes the modular exponentiation using the method of repeated squaring.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:  # If the exponent is odd, multiply the base with the result
            result = (result * base) % mod
        exp = exp >> 1  # Right shift exponent, equivalent to dividing by 2
        base = (base * base) % mod  # Square the base
    return result

def generate_keys():
    """
    Output:
        tuple: A tuple containing the public and private keys.
    Description:
        Generates RSA public and private keys.
    """
    p = generate_large_prime()
    q = generate_large_prime()
    print("Key p: ", p)
    print("Key q: ", q)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = sympy.randprime(2, phi)  # Choose e that is a prime number and coprime to phi
    while sympy.gcd(e, phi) != 1:
        e = sympy.randprime(2, phi)
    d = mod_inverse(e, phi)
    print("Public key (e, n): ", (e, n))
    print("Private key (d, n): ", (d, n))
    
    return (e, n), (d, n)

def encrypt_file(public_key, input_filename, output_filename, block_size=64):
    """
    Inputs:
        public_key (tuple): The public key (e, n).
        input_filename (str): The path to the input file containing plaintext.
        output_filename (str): The path to the output file to write ciphertext.
        block_size (int): The size of each block to be encrypted.
    Description:
        Encrypts a file's contents block-wise and saves the ciphertext to another file.
    """
    with open(input_filename, 'r', encoding='utf-8') as file:
        plaintext = file.read()
    
    e, n = public_key
    block_int_size = n.bit_length() // 8 - 1  # Calculate block size in bytes
    blocks = [plaintext[i:i+block_int_size] for i in range(0, len(plaintext), block_int_size)]

    ciphertext_blocks = []
    for block in blocks:
        m = int.from_bytes(block.encode('utf-8'), 'big')
        if m >= n:
            raise ValueError("Block size too large for the key size")
        c = mod_exp(m, e, n)
        ciphertext_blocks.append(hex(c)[2:])  # Convert ciphertext to hex without '0x'
    
    with open(output_filename, 'w') as file:
        file.write(' '.join(ciphertext_blocks))  # Write hex ciphertext blocks separated by spaces

def decrypt_file(private_key, input_filename, output_filename):
    """
    Inputs:
        private_key (tuple): The private key (d, n).
        input_filename (str): The path to the input file containing ciphertext.
        output_filename (str): The path to the output file to write decrypted text.
    Description:
        Decrypts a file's contents that were encrypted in blocks and saves the plaintext to another file.
    """
    with open(input_filename, 'r') as file:
        ciphertext_blocks = file.read().split()
    
    d, n = private_key
    plaintext_blocks = []
    for block in ciphertext_blocks:
        c = int(block, 16)
        m = mod_exp(c, d, n)
        message_length = (m.bit_length() + 7) // 8
        plaintext_block = m.to_bytes(message_length, 'big').decode('utf-8')
        plaintext_blocks.append(plaintext_block)
    
    with open(output_filename, 'w', encoding='utf-8') as file:
        file.write(''.join(plaintext_blocks))  # Reassemble the plaintext blocks and write

# Key generation
public_key, private_key = generate_keys()

# Encryption
encrypt_file(public_key, 'RSA-test.txt', 'Encrypted-RSA.txt')

# Decryption
decrypt_file(private_key, 'Encrypted-RSA.txt', 'Decrypted-RSA.txt')

print("Encryption and decryption completed.")