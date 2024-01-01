from Crypto.Util.number import getPrime, getRandomRange, inverse
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS


# Load generated keys
def load_key_pairs(public_key_path, private_key_path, dsa_keys_path):
    length = 256

    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big', signed=False)

    print('Loading keys please wait...')

    # Read the key pairs from files
    with open(private_key_path, 'rb') as f:
        private_key_bytes = f.read()
        private_key = bytes_to_int(private_key_bytes)

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
        dsa_public_key = DSA.import_key(dsa_key)
    print('Keys loaded')

    return public_key, private_key, dsa_public_key


def verify_signature(dsa_key, data, signature):
    print("Verifying file signature and hash ...")
    h = SHA256.new(data)
    verifier = DSS.new(dsa_key.publickey(), 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def decrypt(private_key, ciphertext, p):
    print("Decrypting file ...")
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = inverse(s, p)
    plaintext = (c2 * s_inv) % p
    return plaintext


def decrypt_and_verify(public_key, private_key, encrypted_path, signature_path, decrypted_path, dsa_public_key):
    # Read the encrypted data and signature
    with open(encrypted_path, 'rb') as f:
        ciphertext = eval(f.read())
    with open(signature_path, 'rb') as f:
        signature = f.read()

    # Decrypt the data
    plaintext_int = decrypt(private_key, ciphertext, public_key[0])
    plaintext = plaintext_int.to_bytes(
        (plaintext_int.bit_length() + 7) // 8, byteorder='big')

    # Verify the signature
    if verify_signature(dsa_public_key, plaintext, signature):
        print("Signature verified.")

        # Write the decrypted data to a file
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)
        print("File decryption completed")
    else:
        print("Signature verification failed.")
        print("File decryption failed")


if __name__ == "__main__":

    # Users using the algorithm
    user = int(input("Decrypt file, Enter your ID 1 for User 1 OR 2 for User 2: "))

    user1_signature_file_path = 'user_1/signature.sig'
    user2_signature_file_path = 'user_2/signature.sig'
    encrypted_file_path = 'message.enc'
    decrypted_file_path = 'message.dec'
    user1_public_key_path = 'user_1/public_key.pem'
    user2_public_key_path = 'user_2/public_key.pem'
    user1_private_key_path = 'user_1/private_key.pem'
    user2_private_key_path = 'user_2/private_key.pem'
    user1_dsa_public_key_path = 'user_1/dsa_public_key.pem'
    user2_dsa_public_key_path = 'user_1/dsa_public_key.pem'

    # Perform operations

    if user == 1:
        # User 1 will decrypt the file with user 1 private key and verify signature with User 2 dsa public key
        public_key, private_key, dsa_public_key = load_key_pairs(user2_public_key_path,
                                                                 user2_private_key_path, user2_dsa_public_key_path)

        decrypt_and_verify(public_key, private_key, encrypted_file_path,
                           user2_signature_file_path, decrypted_file_path, dsa_public_key)

    elif user == 2:
        # User 2 will decrypt the file with user 2 private key and verify signature with User 1 dsa public key
        public_key, private_key, dsa_public_key = load_key_pairs(user2_public_key_path,
                                                                 user2_private_key_path, user1_dsa_public_key_path)

        decrypt_and_verify(public_key, private_key, encrypted_file_path,
                           user1_signature_file_path, decrypted_file_path, dsa_public_key)
