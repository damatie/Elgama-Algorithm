from Crypto.Util.number import getPrime, getRandomRange
from Crypto.PublicKey import DSA

 # Generate Elgamal keys for encryption and decryption
def generate_elgamal_keys(key_size):
    p = getPrime(key_size)
    g = getRandomRange(2, p - 1)
    x = getRandomRange(1, p - 1)  # Private key for Elgamal
    h = pow(g, x, p)              # Public key for Elgamal
    return (p, g, h), x

 # Generate DSA keys for signing message
def generate_dsa_keys():
    return DSA.generate(2048)

# Save generated Elgamal keys to files
def save_elgamal_keys(public_key, private_key, public_key_path, private_key_path, length=256):

    # Convert integer into a bytes 
    def int_to_bytes(n):
        return n.to_bytes(length, byteorder='big', signed=False)
    
    #  private_key into a bytes 
    with open(private_key_path, 'wb') as f:
        f.write(int_to_bytes(private_key))

    #  public_key into a bytes 
    with open(public_key_path, 'wb') as f:
        for item in public_key:
            f.write(int_to_bytes(item))



# Save generated DSA keys to files
def save_dsa_keys(dsa_key, private_key_path, public_key_path):
    with open(private_key_path, 'wb') as f:
        f.write(dsa_key.export_key(format='PEM'))
    with open(public_key_path, 'wb') as f:
        f.write(dsa_key.publickey().export_key(format='PEM'))

# Initiate both save keys functions for each user
def save_keys_for_user(user_number, key_size):

    # user_number is based on the ID entered in the input 
    # user_dir is the user path to save the keys
    user_dir = f"user_{user_number}/"

    print('Generating keys please wait...')
    # Extract Elgamal keys from function
    elgamal_public_key, elgamal_private_key = generate_elgamal_keys(key_size)

    # Extract DSA keys from function
    dsa_key = generate_dsa_keys()
    

    save_elgamal_keys(elgamal_public_key, elgamal_private_key,
                      user_dir + "public_key.pem", user_dir + "private_key.pem")
    save_dsa_keys(dsa_key, user_dir + "dsa_private_key.pem", user_dir + "dsa_public_key.pem")

    print(f"Keys saved for user {user_number}")

if __name__ == "__main__":
    user = int(input("Generate Key Pairs, Enter 1 for User 1 OR 2 for User 2: "))
    key_size = 1024  # Key size in bits

    # Generate key pairs for selected user
    save_keys_for_user(user, key_size)
