from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad
from Crypto.Util import Counter
from hashlib import pbkdf2_hmac
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# === SECURE KEY DERIVATION FUNCTION ===
def derive_key(password: str, salt: bytes, key_size: int) -> bytes:
    """Derives a secure key from a password using PBKDF2."""
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=key_size)

# === AES ENCRYPTION ===
def encrypt_aes(data, password, mode, iv):
    """Encrypt data using AES with the specified mode."""
    salt = os.urandom(16)  # Generate a random salt for key derivation
    print(salt)
    key = derive_key(password, salt, 32)
    print(key)
    data = data.encode()

    # Ensure the IV is in bytes for non-ECB modes
    if iv:
        # If IV is a string, convert it to bytes (handle both text and hex cases)
        if isinstance(iv, str):
            iv = iv.encode()  # Convert string to bytes directly
        # If IV is in bytes, we don't need to do anything further
        elif isinstance(iv, bytes):
            pass
        else:
            raise ValueError("Invalid IV format")

        # Now pad/truncate the IV to ensure it's 16 bytes long
        if len(iv) < 16:
            iv = iv.ljust(16, b'\0')  # Pad IV to 16 bytes if it's too short
        elif len(iv) > 16:
            iv = iv[:16]  # Truncate IV to 16 bytes if it's too long

    if mode == "ECB":
        print(key)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(data)
    elif mode == "CTR":
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError("Unsupported AES mode")

    # Ensure iv is in bytes and concatenate as hex strings
    iv_hex = iv.hex() if iv else ''
    return salt.hex() + iv_hex + ciphertext.hex()

# === 3DES ENCRYPTION ===
def encrypt_3des(data, password, mode, iv):
    """Encrypt data using 3DES with the specified mode."""
    salt = os.urandom(16)  # Generate a random salt for key derivation
    key = derive_key(password, salt, 24)  # 3DES requires a 24-byte key
    data = data.encode()

    # Ensure the IV is in bytes for non-ECB modes
    if iv:
        # If IV is a string, convert it to bytes (handle both text and hex cases)
        if isinstance(iv, str):
            iv = iv.encode()  # Convert string to bytes directly
        # If IV is in bytes, we don't need to do anything further
        elif isinstance(iv, bytes):
            pass
        else:
            raise ValueError("Invalid IV format")

        # Now pad/truncate the IV to ensure it's 8 bytes long (since 3DES uses 64-bit blocks)
        if len(iv) < 8:
            iv = iv.ljust(8, b'\0')  # Pad IV to 8 bytes if it's too short
        elif len(iv) > 8:
            iv = iv[:8]  # Truncate IV to 8 bytes if it's too long

    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    elif mode == "CBC":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    elif mode == "CFB":
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        ciphertext = cipher.encrypt(data)
    elif mode == "CTR":
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, 'big'))
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError("Unsupported 3DES mode")

    # Ensure iv is in bytes and concatenate as hex strings
    iv_hex = iv.hex() if iv else ''
    return salt.hex() + iv_hex + ciphertext.hex()

# === OTP ENCRYPTION ===
def encrypt_otp(data, key):
    """Encrypt data using One-Time Pad (OTP)."""
    data = data.encode()
    key = key.encode()

    # Handle the case where the key is shorter than the data
    if len(key) < len(data):
        # Repeat the key to match the length of the data
        key = (key * ((len(data) // len(key)) + 1))[:len(data)]
    
    # Handle the case where the key is longer than the data (truncate it)
    elif len(key) > len(data):
        key = key[:len(data)]

    ciphertext = bytes([d ^ k for d, k in zip(data, key)])
    return ciphertext.hex()

def generate_password(algorithm: str, ciphertext_length: int = None):
    """
    Generates a secure key for the specified algorithm.
    
    :param algorithm: The encryption algorithm ('AES', '3DES', or 'OTP')
    :param ciphertext_length: The length of the ciphertext (only used for OTP)
    :return: The generated key as a byte string
    """
    if algorithm == "aes":
        # AES requires a 256-bit key (32 bytes)
        return os.urandom(32)  # Generate 32 random bytes
    elif algorithm == "des":
        # 3DES requires a 192-bit key (24 bytes)
        return os.urandom(24)  # Generate 24 random bytes
    elif algorithm == "otp":
        if ciphertext_length is None:
            raise ValueError("For OTP, the key length must match the ciphertext length.")
        # OTP key length must match the ciphertext length
        return os.urandom(ciphertext_length)  # Generate a random key of the required length
    else:
        raise ValueError("Unsupported algorithm. Please choose 'AES', '3DES', or 'OTP'.")
    
def generate_iv(algorithm: str, mode: str):
    """
    Generates a secure IV for the specified algorithm and mode.
    
    :param algorithm: The encryption algorithm ('AES' or '3DES')
    :param mode: The encryption mode ('CBC', 'CFB')
    :return: The generated IV as a byte string
    """
    if algorithm == "aes":
        if mode in ["CBC", "CFB", "CTR"]:
            # AES requires a 128-bit IV (16 bytes) for CBC and CFB modes
            return os.urandom(16)  # Generate 16 random bytes
        else:
            raise ValueError("Unsupported AES mode. Choose from 'CBC', 'CFB', 'CTR'.")

    elif algorithm == "des":
        if mode in ["CBC", "CFB", "CTR"]:
            # 3DES requires a 64-bit IV (8 bytes) for CBC and CFB modes
            return os.urandom(8)  # Generate 8 random bytes
        else:
            raise ValueError("Unsupported 3DES mode. Choose from 'CBC', 'CFB', 'CTR'.")
    
    else:
        raise ValueError("Unsupported algorithm. Please choose 'AES' or '3DES'.")

# === RAS ENCRYPTION ===

KEYS_DIR = "./keys"

def load_or_generate_keys():
    # Ensure the keys directory exists
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    private_key_path = os.path.join(KEYS_DIR, "private_key.pem")
    public_key_path = os.path.join(KEYS_DIR, "public_key.pem")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        # If the keys exist, load and return them
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
    
    else:

        # If keys do not exist, generate new ones
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()
        
        # Save the generated keys to files
        with open(private_key_path, "wb") as f:
            f.write(private_key.export_key())
        with open(public_key_path, "wb") as f:
            f.write(public_key.export_key())
    print(type(public_key))
        
    return private_key, public_key

def rsa_encrypt(plain_text, public_key):
    # Create a cipher object using the public key
    cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(plain_text.encode())
    
    # Return the encrypted message encoded in base64 for easy storage or transmission
    return base64.b64encode(encrypted_message).decode('utf-8')

