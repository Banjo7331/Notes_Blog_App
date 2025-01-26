from cryptography.fernet import Fernet

def generate_otp_encryption_key():
    key = Fernet.generate_key()
    print("Generated Encryption Key:", key.decode())

if __name__ == "__main__":
    generate_otp_encryption_key()