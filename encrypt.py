from Crypto.Util.number import getRandomRange
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)

def load_elgamal_public_key(file_path):
    length = 256
    with open(file_path, 'rb') as f:
        p, g, h = (bytes_to_int(f.read(length)) for _ in range(3))
    return (p, g, h)

def load_dsa_private_key(file_path):
    with open(file_path, 'rb') as f:
        return DSA.import_key(f.read())

def sign_data(dsa_key, data):
    h = SHA256.new(data)
    signer = DSS.new(dsa_key, 'fips-186-3')
    return signer.sign(h)

def encrypt_data(public_key, plaintext):
    p, g, h = public_key
    k = getRandomRange(1, p - 1)
    s = pow(h, k, p)
    c1 = pow(g, k, p)
    c2 = (plaintext * s) % p
    return (c1, c2)

def encrypt_and_sign(user_id, input_file, encrypted_file, signature_file):
    # Load keys
    elgamal_public_key = load_elgamal_public_key(f'user_{3 - user_id}/public_key.pem')
    dsa_private_key = load_dsa_private_key(f'user_{user_id}/dsa_private_key.pem')

    # Read the input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt the plaintext and sign it
    ciphertext = encrypt_data(elgamal_public_key, int.from_bytes(plaintext, byteorder='big'))
    signature = sign_data(dsa_private_key, plaintext)

    # Write the encrypted data and signature to files
    with open(encrypted_file, 'wb') as f:
        f.write(str(ciphertext).encode())
    with open(signature_file, 'wb') as f:
        f.write(signature)

    print(f"File encrypted and signed by User {user_id}")

def main():
    user_id = int(input("Encrypt message: Enter your ID (1 for User 1 OR 2 for User 2): "))
    input_file_path = 'message.txt'
    encrypted_file_path = 'message.enc'
    signature_file_path = f'user_{user_id}/signature.sig'

    encrypt_and_sign(user_id, input_file_path, encrypted_file_path, signature_file_path)

if __name__ == "__main__":
    main()