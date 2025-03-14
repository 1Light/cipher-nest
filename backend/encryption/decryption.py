from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from hashlib import pbkdf2_hmac
import os

# === SECURE KEY DERIVATION FUNCTION ===
def derive_key(password: str, salt: bytes, key_size: int) -> bytes:
    """Derives a secure key from a password using PBKDF2."""
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=key_size)

# === AES DECRYPTION ===
def decrypt_aes(ciphertext_hex, password, mode, iv=None):
    """Decrypt data using AES with the specified mode."""
    # Convert the ciphertext from hex to bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    # Extract the salt and ciphertext (first 16 bytes is salt, rest is ciphertext)
    salt = ciphertext_bytes[:16]
    ciphertext = ciphertext_bytes[16:]

    # For CBC, CFB, and CTR modes, extract the IV from the ciphertext if not passed
    if mode in ["CBC", "CFB", "CTR"] and iv is None:
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]  # Remaining part is the actual ciphertext

    if iv is None:
        iv = None  # ECB mode does not use an IV

    # Derive the key from the password and salt
    key = derive_key(password, salt, 32)

    # Ensure IV is in bytes and properly padded/truncated for the mode
    if iv:
        if isinstance(iv, str):
            iv = iv.encode()  # Convert string to bytes
            print(iv)
        elif isinstance(iv, bytes):
            pass
        else:
            raise ValueError("Invalid IV format")

        # Pad/truncate the IV to 16 bytes (since AES requires 128-bit blocks)
        iv = iv.ljust(16, b'\0') if len(iv) < 16 else iv[:16]

    # Perform decryption based on the mode
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print(plaintext)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
    elif mode == "CTR":
        if iv is None:
            raise ValueError("IV is required for CTR mode")
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
    else:
        raise ValueError("Unsupported AES mode")
    
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext.hex()

# === 3DES DECRYPTION ===
def decrypt_3des(ciphertext_hex, password, mode, iv=None):
    """Decrypt data using 3DES with the specified mode."""
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    salt, ciphertext = ciphertext_bytes[:16], ciphertext_bytes[16:]
    key = derive_key(password, salt, 24)

    if mode in ["CBC", "CFB"] and iv is None:
        iv, ciphertext = ciphertext[:8], ciphertext[8:]  # 3DES IV is 8 bytes

    # Ensure IV is in bytes and properly padded/truncated for the mode
    if iv:
        if isinstance(iv, str):
            iv = iv.encode()  # Convert string to bytes
        elif isinstance(iv, bytes):
            pass
        else:
            raise ValueError("Invalid IV format")

        # Pad/truncate the IV to 8 bytes (since 3DES requires 64-bit blocks)
        iv = iv.ljust(8, b'\0') if len(iv) < 8 else iv[:8]

    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
    elif mode == "CTR":
        ctr = Counter.new(64)
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
    else:
        raise ValueError("Unsupported 3DES mode")
    
    return plaintext.decode()

# === OTP DECRYPTION ===
def decrypt_otp(ciphertext_hex, key):
    """Decrypt data using One-Time Pad (OTP)."""
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = key.encode()

    if len(key) < len(ciphertext):
        raise ValueError("Key must be at least as long as ciphertext for OTP decryption")

    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext.decode()