import json
from django.shortcuts import render
from .encryption import encrypt_aes, encrypt_3des, encrypt_otp, generate_iv, generate_key
from .decryption import decrypt_aes, decrypt_3des, decrypt_otp
from django.http import JsonResponse

def index(request):

    return render(request, "index.html")

# === Encryption View ===
def encrypt_view(request):
    encrypted_message = ''
    if request.method == 'POST':
        print(request.POST)
        algorithm = request.POST.get('hiddenEncryptionMethod')
        mode = request.POST.get('encryptionMode')
        iv = request.POST.get('encryptionIV')
        key = request.POST.get('encryptionKey')
        message = request.POST.get('encryptMessage')

        # Validate the message
        if not message:
            return JsonResponse({"error": "Please enter a message to encrypt."}, status=400)

        # Validate the key
        if not key:
            return JsonResponse({"error": "Please enter an encryption key."}, status=400)

        # Validate IV if necessary (only for modes other than ECB)
        if mode != "ECB" and not iv:
            return JsonResponse({"error": "Please enter an Initialization Vector (IV)."}, status=400)

        if message:
            if algorithm == "aes":
                encrypted_message = encrypt_aes(message, key, mode, iv)
            elif algorithm == "des":
                encrypted_message = encrypt_3des(message, key, mode, iv)
            elif algorithm == "otp":
                encrypted_message = encrypt_otp(message, key)
            else:
                encrypted_message = "Invalid Algorithm"

    print(encrypted_message)
    return JsonResponse({'encrypted_message': encrypted_message})

# === Decryption View ===
def decrypt_view(request):
    decrypted_message = ''
    if request.method == 'POST':
        algorithm = request.POST.get('hiddenDecryptionMethod')
        mode = request.POST.get('decryptionMode') 
        key = request.POST.get('decryptionKey')
        ciphertext = request.POST.get('decryptMessage')

        # Validate the message
        if not ciphertext:
            return JsonResponse({"error": "Please enter a message to decrypt."}, status=400)

        # Validate the key
        if not key:
            return JsonResponse({"error": "Please enter an decryption key."}, status=400)

        if ciphertext:
            if algorithm == "aes":
                decrypted_message = decrypt_aes(ciphertext, key, mode)
            elif algorithm == "des":
                decrypted_message = decrypt_3des(ciphertext, key, mode)
            elif algorithm == "otp":
                decrypted_message = decrypt_otp(ciphertext, key)  
            else:
                decrypted_message = "Invalid Algorithm"
        
    print(decrypted_message)

    return JsonResponse({'decrypted_message': decrypted_message})

def generate_key_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            algorithm = data.get("algorithm")
            ciphertext_length = data.get("ciphertext_length", None)

            # Convert ciphertext_length to integer if provided
            if ciphertext_length:
                ciphertext_length = int(ciphertext_length)

            key = generate_key(algorithm, ciphertext_length)

            print(key)
            return JsonResponse({"key": key.hex()}, status=200)  
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request"}, status=400)

def generate_iv_view(request):
    if request.method == "POST":
        try:
            # Parse the JSON data from the request
            data = json.loads(request.body)
            
            # Extract algorithm and mode from the request data
            algorithm = data.get("algorithm")
            mode = data.get("mode")
            
            # Validate the required parameters
            if not algorithm or not mode:
                return JsonResponse({"error": "Algorithm and mode are required."}, status=400)

            # Generate the IV using the provided algorithm and mode
            iv = generate_iv(algorithm, mode)

            # Return the IV as a hex string in the response
            return JsonResponse({"iv": iv.hex()}, status=200)
        
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    
    return JsonResponse({"error": "Invalid request. Only POST method is allowed."}, status=400)