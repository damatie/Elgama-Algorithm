from Crypto.Util.number import getRandomRange
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# Function to convert bytes to an integer
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)

# Function to load ElGamal public key from a file
def load_elgamal_public_key(file_path):
    length = 256  # Define the byte length for each key component
    with open(file_path, 'rb') as f:
        # Read p, g, h values from file and convert to integers
        p, g, h = (bytes_to_int(f.read(length)) for _ in range(3))
    return (p, g, h)

# Function to load a DSA private key from a file
def load_dsa_private_key(file_path):
    with open(file_path, 'rb') as f:
        # Import the DSA key from the file
        return DSA.import_key(f.read())

# Function to sign data using a DSA private key
def sign_data(dsa_key, data):
    h = SHA256.new(data)  # Hash the data using SHA256
    signer = DSS.new(dsa_key, 'fips-186-3')  # Create a DSS signer with FIPS 186-3 standard
    return signer.sign(h)  # Sign the hashed data and return the signature

# Function to encrypt data using ElGamal encryption
def encrypt_data(public_key, plaintext):
    p, g, h = public_key
    k = getRandomRange(1, p - 1)  # Generate a random number k
    s = pow(h, k, p)  # Compute s = h^k mod p
    c1 = pow(g, k, p)  # Compute c1 = g^k mod p
    c2 = (plaintext * s) % p  # Compute c2 = (plaintext * s) mod p
    return (c1, c2)  # Return the ciphertext tuple (c1, c2)

# Main function to encrypt and sign a file
def encrypt_and_sign(user_id, input_file, encrypted_file, signature_file):
    # Load the ElGamal public key and DSA private key
    elgamal_public_key = load_elgamal_public_key(f'user_{3 - user_id}/public_key.pem')
    dsa_private_key = load_dsa_private_key(f'user_{user_id}/dsa_private_key.pem')

    # Read plaintext data from the input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt the plaintext and create a digital signature
    ciphertext = encrypt_data(elgamal_public_key, int.from_bytes(plaintext, byteorder='big'))
    signature = sign_data(dsa_private_key, plaintext)

    # Write the encrypted data and signature to separate files
    with open(encrypted_file, 'wb') as f:
        f.write(str(ciphertext).encode())
    with open(signature_file, 'wb') as f:
        f.write(signature)

    # Print confirmation message
    print(f"File encrypted and signed by User {user_id}")

# Entry point of the script
def main():
    # Prompt user for their ID and set file paths
    user_id = int(input("Encrypt message: Enter your ID (1 for User 1 OR 2 for User 2): "))
    input_file_path = 'message.txt'
    encrypted_file_path = 'message.enc'
    signature_file_path = f'user_{user_id}/signature.sig'

    # Perform encryption and signing
    encrypt_and_sign(user_id, input_file_path, encrypted_file_path, signature_file_path)

# Check if the script is being run directly
if __name__ == "__main__":
    main()
