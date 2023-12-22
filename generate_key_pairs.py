from Crypto.Util.number import getPrime, getRandomRange
from Crypto.PublicKey import DSA
import struct


def generate_keys(key_size):
    p = getPrime(key_size)
    g = getRandomRange(2, p - 1)
    x = getRandomRange(1, p - 1)  # Private key for Elgamal
    h = pow(g, x, p)              # Public key for Elgamal

    # Generate DSA keys for signing
    dsa_key = DSA.generate(2048)

    return ((p, g, h), x, dsa_key)


# Save generated keys to files
def save_key_pairs(public_key_path, private_key_path, user1_dsa_private_key_path, user1_dsa_public_key_path):
    length = 256

    print('Generating keys please wait...')

    def int_to_bytes(n, length):
        return n.to_bytes(length, byteorder='big', signed=False)

    public_key, private_key, dsa_key = generate_keys(key_size)

    print('Saving keys please wait...')

    # Write the key pairs to files
    with open(private_key_path, 'wb') as f:
        f.write(int_to_bytes(private_key, length))

    with open(public_key_path, 'wb') as f:

        for item in public_key:
            f.write(int_to_bytes(item, length))

  # # Save the dsa keys
    private_dsa_key = dsa_key.export_key(format='PEM')
    public_dsa_key = dsa_key.publickey().export_key(format='PEM')

    with open(user1_dsa_private_key_path, 'wb') as f:
        f.write(private_dsa_key)

    with open(user1_dsa_public_key_path, 'wb') as f:
        f.write(public_dsa_key)

    print('Keys saved')


if __name__ == "__main__":

   # Users using the algorithm
    user = int(input("Generate Key Pairs, Enter 1 for User 1 OR 2 for User 2: "))

    # Example usage
    key_size = 1024  # Key size in bits

    user1_public_key_path = 'Cryptography/Elgama/user_1/public_key.pem'
    user1_private_key_path = 'Cryptography/Elgama/user_1/private_key.pem'
    user1_dsa_private_key_path = 'Cryptography/Elgama/user_1/dsa_private_key.pem'
    user1_dsa_public_key_path = 'Cryptography/Elgama/user_1/dsa_public_key.pem'
    user2_public_key_path = 'Cryptography/Elgama/user_2/public_key.pem'
    user2_private_key_path = 'Cryptography/Elgama/user_2/private_key.pem'
    user2_dsa_private_key_path = 'Cryptography/Elgama/user_2/dsa_private_key.pem'
    user2_dsa_public_key_path = 'Cryptography/Elgama/user_2/dsa_public_key.pem'

    # Generate key pairs for 2 users
    if user == 1:
        save_key_pairs(user1_public_key_path,
                       user1_private_key_path, user1_dsa_private_key_path, user1_dsa_public_key_path)
    elif user == 2:
        save_key_pairs(user2_public_key_path,
                       user2_private_key_path, user2_dsa_private_key_path, user2_dsa_public_key_path)
