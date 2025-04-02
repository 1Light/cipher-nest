from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from hashlib import pbkdf2_hmac
from Crypto.Cipher import PKCS1_OAEP
import base64
import binascii

# === SECURE KEY DERIVATION FUNCTION ===
def derive_key(password: str, salt: bytes, key_size: int) -> bytes:
    """Derives a secure key from a password using PBKDF2."""
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=key_size)

# === AES DECRYPTION ===
def decrypt_aes(ciphertext_hex, password, mode):
    """Decrypt AES-encrypted data, properly extracting salt, IV, and ciphertext."""
    # Convert hex input to bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    # Extract the salt (first 16 bytes)
    salt = ciphertext_bytes[:16]
    key = derive_key(password, salt, 32)

    # Determine IV length (16 bytes for CBC, CFB, and CTR modes; 0 for ECB)
    iv_length = 16 if mode in ["CBC", "CFB", "CTR"] else 0

    # Extract IV (next 16 bytes if applicable)
    iv = ciphertext_bytes[16:16+iv_length] if iv_length else None

    # Extract the actual ciphertext (remaining bytes)
    ciphertext = ciphertext_bytes[16+iv_length:]

    print(f"\n--- DEBUG INFO ---")
    print(f"Salt (Hex): {binascii.hexlify(salt)}")
    print(f"Derived Key (Hex): {binascii.hexlify(key)}")
    if iv:
        print(f"Extracted IV (Hex): {binascii.hexlify(iv)}")
    print(f"Ciphertext (Hex): {binascii.hexlify(ciphertext)}")

    # Perform decryption based on mode
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
    elif mode == "CTR":
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
    else:
        return "Unsupported AES mode"

    print(f"Decrypted Bytes (Hex): {binascii.hexlify(plaintext)}")
    decrypted_text = plaintext.decode("utf-8", errors="ignore")
    print(f"Decrypted Text: {decrypted_text}")
    print(f"--------------------\n")

    return decrypted_text


# === 3DES DECRYPTION ===
def decrypt_3des(ciphertext_hex, password, mode):
    """Decrypt data using 3DES with the specified mode."""
    # Convert the ciphertext from hex to bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    # Extract the salt (first 16 bytes) and the ciphertext (after salt)
    salt = ciphertext_bytes[:16]
    ciphertext = ciphertext_bytes[16:]

    # Derive the key from the password and salt
    key = derive_key(password, salt, 24)  # 3DES needs a 24-byte key

    # Determine IV length (8 bytes for CBC, CFB, and CTR modes; 0 for ECB)
    iv_length = 8 if mode in ["CBC", "CFB", "CTR"] else 0

    # Extract IV (next 8 bytes if applicable)
    iv = ciphertext[:iv_length] if iv_length else None
    ciphertext = ciphertext[iv_length:]  # Remaining is ciphertext

    print(f"\n--- DEBUG INFO ---")
    print(f"Salt (Hex): {binascii.hexlify(salt)}")
    print(f"Derived Key (Hex): {binascii.hexlify(key)}")
    if iv:
        print(f"Extracted IV (Hex): {binascii.hexlify(iv)}")
    print(f"Ciphertext (Hex): {binascii.hexlify(ciphertext)}")

    # Perform decryption based on the mode
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif mode == "CBC":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif mode == "CFB":
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
    elif mode == "CTR":
        # Use the IV to initialize the counter for CTR mode
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, 'big'))
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
    else:
        raise ValueError("Unsupported 3DES mode")

    print(f"Decrypted Bytes (Hex): {binascii.hexlify(plaintext)}")
    decrypted_text = plaintext.decode("utf-8", errors="ignore")
    print(f"Decrypted Text: {decrypted_text}")
    print(f"--------------------\n")

    return decrypted_text

# === OTP DECRYPTION ===
def decrypt_otp(ciphertext_hex, key):
    """Decrypt data using One-Time Pad (OTP)."""
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = key.encode()

    if len(key) < len(ciphertext):
        raise ValueError("Key must be at least as long as ciphertext for OTP decryption")

    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext.decode()

# === RAS ENCRYPTION ===
def rsa_decrypt(encrypted_text, private_key):
    # Decode the encrypted message from base64
    encrypted_message = base64.b64decode(encrypted_text.encode())
    
    # Create a cipher object using the private key
    cipher = PKCS1_OAEP.new(private_key)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    
    return decrypted_message