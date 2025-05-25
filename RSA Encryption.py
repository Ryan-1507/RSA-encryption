# imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os


# Function to generate RSA keys (both public and private keys)
def generate_rsa_keys():
    # Generate a private RSA key. The key size is 2048 bits, providing strong security.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Extract the public key from the generated private key.
    public_key = private_key.public_key()

    # Convert the private key to a standard format called PEM, without any password protection.
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Convert the public key to PEM format as well.
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public


# Function to read file contents. Used for reading the files to encrypt or decrypt.
def read_file(file_path):
    if not os.path.exists(file_path):
        return None

    with open(file_path, 'rb') as file:
        return file.read()


# Function to write content to a file. This is used to write encrypted or decrypted data back to a file.
def write_file(file_path, content):
    with open(file_path, 'wb') as file:
        file.write(content)


# Function to encrypt data using the public key.
def encrypt_with_rsa(public_key_pem, message):
    # Load the public key from its PEM format.
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    # Encrypt the message using the public key and OAEP padding for security.
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


# Function to decrypt data using the private key.
def decrypt_with_rsa(private_key_pem, encrypted_message):
    # Load the private key from its PEM format.
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Try to decrypt the message using the private key. If it fails, return None.
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message
    except InvalidSignature:
        return None


# Function to encrypt all text files in a specified directory.
def encrypt_files_in_directory(directory_path, public_key_pem):
    if not os.path.isdir(directory_path):
        print("Invalid directory.")
        return

    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory_path, filename)
            file_contents = read_file(file_path)
            if file_contents is not None:
                encrypted_data = encrypt_with_rsa(public_key_pem, file_contents)
                write_file(file_path + '.encrypted', encrypted_data)

    print(f"All .txt files in {directory_path} have been encrypted.")


# Main function - the starting point of the program. It handles user inputs and calls the appropriate functions.
def main():
    # Generate RSA keys at the start of the program.
    private_key, public_key = generate_rsa_keys()

    while True:
        # Display the menu options.
        print("\nRSA Encryption Tool")
        print("1. Encrypt a file")
        print("2. Encrypt all .txt files in a directory")
        print("3. Decrypt a file")
        print("4. Print keys")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            # Option to encrypt a single file.
            file_path = input("Enter the path of the file to encrypt: ")
            file_contents = read_file(file_path)
            if file_contents is not None:
                encrypted_data = encrypt_with_rsa(public_key, file_contents)
                write_file(file_path + '.encrypted', encrypted_data)
                print(f"File encrypted and saved as {file_path}.encrypted")
            else:
                print("File not found or is empty.")

        elif choice == '2':
            # Option to encrypt all text files in a specified directory.
            directory_path = input("Enter the path of the directory: ")
            encrypt_files_in_directory(directory_path, public_key)

        elif choice == '3':
            # Option to decrypt an encrypted file.
            file_path = input("Enter the path of the encrypted file to decrypt: ")
            file_contents = read_file(file_path)
            if file_contents is not None:
                decrypted_data = decrypt_with_rsa(private_key, file_contents)
                if decrypted_data:
                    write_file(file_path.replace('.encrypted', '.decrypted'), decrypted_data)
                    print(f"File decrypted and saved as {file_path}.decrypted")
                else:
                    print("Decryption failed. The file may be corrupted or the wrong key used.")
            else:
                print("File not found or is empty.")

        elif choice == '4':
            # Option to print the currently used RSA keys.
            print("\nPublic Key:\n", public_key.decode())
            print("\nPrivate Key:\n", private_key.decode())

        elif choice == '5':
            # Option to exit the program.
            print("Exiting the program.")
            break

        else:
            # Handling invalid menu choices.
            print("Invalid choice. Please choose a valid option.")


# The starting point of the script execution.
if __name__ == "__main__":
    main()
