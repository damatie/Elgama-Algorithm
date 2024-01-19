from Crypto.Util.number import inverse
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# Convert a bytes object to an integer
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)

# Load ElGamal private key from a file
def load_elgamal_private_key(file_path):
    length = 256  # Define the byte length for the key
    with open(file_path, 'rb') as f:
        # Read the private key and convert it to an integer
        private_key = bytes_to_int(f.read(length))
    return private_key

# Load ElGamal public key from a file
def load_elgamal_public_key(file_path):
    length = 256  # Define the byte length for each key component
    with open(file_path, 'rb') as f:
        # Read p, g, h values from file and convert them to integers
        p, g, h = (bytes_to_int(f.read(length)) for _ in range(3))
    return (p, g, h)

# Load DSA public key from a file
def load_dsa_public_key(file_path):
    with open(file_path, 'rb') as f:
        # Import the DSA public key from the file
        return DSA.import_key(f.read())

# Decrypt data using ElGamal decryption algorithm
def decrypt_data(ciphertext, private_key, public_key):
    p, g, h = public_key
    c1, c2 = ciphertext
    # Calculate the inverse of s (s = c1^private_key mod p)
    s_inv = inverse(pow(c1, private_key, p), p)
    # Decrypt the plaintext
    plaintext = (c2 * s_inv) % p
    # Convert the plaintext from integer to bytes
    return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')

# Verify a digital signature using DSA
def verify_signature(dsa_public_key, data, signature):
    h = SHA256.new(data)  # Hash the data using SHA256
    verifier = DSS.new(dsa_public_key, 'fips-186-3')  # Create a DSS verifier with FIPS 186-3 standard
    try:
        verifier.verify(h, signature)  # Verify the signature
        return True
    except ValueError:
        return False

# Decrypt an encrypted file and verify its signature
def decrypt_and_verify(user_id, encrypted_file, signature_file, decrypted_file):
    # Load the ElGamal private key, ElGamal public key, and DSA public key
    elgamal_private_key = load_elgamal_private_key(f'user_{user_id}/private_key.pem')
    elgamal_public_key = load_elgamal_public_key(f'user_{user_id}/public_key.pem')
    dsa_public_key = load_dsa_public_key(f'user_{3 - user_id}/dsa_public_key.pem')

    # Read the encrypted data and signature from files
    with open(encrypted_file, 'rb') as f:
        ciphertext = eval(f.read())
    with open(signature_file, 'rb') as f:
        signature = f.read()

    # Decrypt the data and verify the signature
    plaintext = decrypt_data(ciphertext, elgamal_private_key, elgamal_public_key)
    if verify_signature(dsa_public_key, plaintext, signature):
        # If signature is valid, write the decrypted data to a file
        with open(decrypted_file, 'wb') as f:
            f.write(plaintext)
        print("Decryption and signature verification successful.")
    else:
        # If signature is invalid, print an error message
        print("Signature verification failed.")

# Entry point of the script
def main():
    # Prompt user for their ID and set file paths
    user_id = int(input("Decrypt message: Enter your ID (1 for User 1 OR 2 for User 2): "))
    encrypted_file_path = 'message.enc'
    signature_file_path = f'user_{3 - user_id}/signature.sig'
    decrypted_file_path = 'message.dec'

    # Perform decryption and signature verification
    decrypt_and_verify(user_id, encrypted_file_path, signature_file_path, decrypted_file_path)

# Check if the script is being run directly
if __name__ == "__main__":
    main()
