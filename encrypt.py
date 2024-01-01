from Crypto.Util.number import getRandomRange
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS


# Load generated keys
def load_key_pairs(public_key_path, dsa_keys_path):
    length = 256

    print('Loading keys please wait...')

    # Read the key pairs from files

    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big', signed=False)

    with open(public_key_path, 'rb') as f:
        # public_key = f.read()
        p_bytes = f.read(length)
        g_bytes = f.read(length)
        h_bytes = f.read(length)

        p = bytes_to_int(p_bytes)
        g = bytes_to_int(g_bytes)
        h = bytes_to_int(h_bytes)

        public_key = (p, g, h)

  # Read the dsa keys
    with open(dsa_keys_path, 'rb') as f:
        dsa_key = f.read()
        dsa_private_key = DSA.import_key(dsa_key)

    print('Keys loaded')

    return public_key, dsa_private_key


# Sign hash file
def sign_hash_file(dsa_key, data):
    print("Signing and hasing file ...")
    h = SHA256.new(data)
    signer = DSS.new(dsa_key, 'fips-186-3')
    signature = signer.sign(h)

    return signature


# Encrypt file
def encrypt(public_key, plaintext):
    print("Encrypting file ...")
    p, g, h = public_key

    k = getRandomRange(1, p - 1)
    s = pow(h, k, p)
    c1 = pow(g, k, p)
    c2 = (plaintext * s) % p

    return (c1, c2)


# Encrypt and sign
def encrypt_and_sign(public_key, dsa_private_key, file_path, encrypted_path, signature_path):

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt the plaintext
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    ciphertext = encrypt(public_key, plaintext_int)

    # Sign the plaintext
    signature = sign_hash_file(dsa_private_key, plaintext)

    # Write the encrypted data and signature to files
    with open(encrypted_path, 'wb') as f:
        f.write(str(ciphertext).encode())
    with open(signature_path, 'wb') as f:
        f.write(signature)

    print("File encryption completed")


if __name__ == "__main__":

    # Users using the algorithm
    user = int(
        input("Encrypt file, Enter your ID. 1 for User 1 OR 2 for User 2: "))

    input_file_path = 'message.txt'
    user1_signature_file_path = 'signature.sig'
    user2_signature_file_path = 'user_2/signature.sig'
    encrypted_file_path = 'message.enc'
    user1_public_key_path = 'user_1/public_key.pem'
    user2_public_key_path = 'user_2/public_key.pem'
    user1_dsa_private_key_path = 'user_1/dsa_private_key.pem'
    user2_dsa_private_key_path = 'user_2/dsa_private_key.pem'

    # Perform operations
    if user == 1:
        # User 1 will encrypt the file with user 2 public key and sign with User 1 dsa private key
        public_key, dsa_private_key = load_key_pairs(
            user2_public_key_path,  user1_dsa_private_key_path)

        encrypt_and_sign(public_key, dsa_private_key, input_file_path,
                         encrypted_file_path, user1_signature_file_path)

    elif user == 2:
        # User 2 will encrypt the file with user 1 public key and sign with User 2 dsa private key
        public_key, dsa_private_key = load_key_pairs(
            user1_public_key_path,  user2_dsa_private_key_path)

        encrypt_and_sign(public_key, dsa_private_key, input_file_path,
                         encrypted_file_path, user2_signature_file_path)
