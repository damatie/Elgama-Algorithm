from Crypto.Util.number import inverse
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)

def load_elgamal_private_key(file_path):
    length = 256
    with open(file_path, 'rb') as f:
        private_key = bytes_to_int(f.read(length))
    return private_key

def load_elgamal_public_key(file_path):
    length = 256
    with open(file_path, 'rb') as f:
        p, g, h = (bytes_to_int(f.read(length)) for _ in range(3))
    return (p, g, h)

def load_dsa_public_key(file_path):
    with open(file_path, 'rb') as f:
        return DSA.import_key(f.read())

def decrypt_data(ciphertext, private_key, public_key):
    p, g, h = public_key
    c1, c2 = ciphertext
    s_inv = inverse(pow(c1, private_key, p), p)
    plaintext = (c2 * s_inv) % p
    return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')

def verify_signature(dsa_public_key, data, signature):
    h = SHA256.new(data)
    verifier = DSS.new(dsa_public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def decrypt_and_verify(user_id, encrypted_file, signature_file, decrypted_file):
    # Load keys
    elgamal_private_key = load_elgamal_private_key(f'user_{user_id}/private_key.pem')
    elgamal_public_key = load_elgamal_public_key(f'user_{user_id}/public_key.pem')
    dsa_public_key = load_dsa_public_key(f'user_{3 - user_id}/dsa_public_key.pem')

    # Read the encrypted data and signature
    with open(encrypted_file, 'rb') as f:
        ciphertext = eval(f.read())
    with open(signature_file, 'rb') as f:
        signature = f.read()

    # Decrypt the data and verify the signature
    plaintext = decrypt_data(ciphertext, elgamal_private_key, elgamal_public_key)
    if verify_signature(dsa_public_key, plaintext, signature):
        with open(decrypted_file, 'wb') as f:
            f.write(plaintext)
        print("Decryption and signature verification successful.")
    else:
        print("Signature verification failed.")

def main():
    user_id = int(input("Decrypt message: Enter your ID (1 for User 1 OR 2 for User 2): "))
    encrypted_file_path = 'message.enc'
    signature_file_path = f'user_{3 - user_id}/signature.sig'
    decrypted_file_path = 'message.dec'

    decrypt_and_verify(user_id, encrypted_file_path, signature_file_path, decrypted_file_path)

if __name__ == "__main__":
    main()
