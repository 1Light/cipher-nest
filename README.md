# Cipher Nest

## Overview
Cipher Nest is a web-based encryption and decryption tool that utilizes AES, 3DES, and OTP encryption algorithms. It supports multiple encryption modes, including ECB, CBC, CFB, and CTR for AES and 3DES. The application is built using Django for the backend and a modern frontend stack including HTML, CSS, Bootstrap, Dart Sass, Autoprefixer, and PostCSS. It also features AJAX for real-time rendering without page reloads.

## Features
- **Encryption & Decryption**: Supports AES, 3DES, and OTP encryption methods.
- **Multiple Modes**: AES and 3DES support ECB, CBC, CFB, and CTR modes.
- **Real-Time Processing**: Uses AJAX for encryption and decryption without reloading the page.
- **User-friendly Interface**: Built with Bootstrap for responsiveness and ease of use.
- **Modern Frontend Stack**: Uses Dart Sass, Autoprefixer, and PostCSS for efficient styling.
- **Secure Implementation**: Ensures data security through cryptographic best practices.

## Technologies Used
### Backend
- Django (Python)
- Django REST Framework
- Cryptographic libraries for encryption/decryption

### Frontend
- HTML, CSS, JavaScript
- Bootstrap for UI design
- AJAX for real-time processing
- Dart Sass for advanced styling
- Autoprefixer & PostCSS for CSS optimization

## Installation & Setup
1. **Clone the Repository**
   ```bash
   git clone https://github.com/1Light/cipher-nest.git
   cd backend
   ```
2. **Set Up Virtual Environment**
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows use `env\Scripts\activate`
   ```
3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run Database Migrations** (if applicable)
   ```bash
   python manage.py migrate
   ```
5. **Start Development Server**
   ```bash
   python manage.py runserver
   ```
6. **Install Frontend Dependencies**
   ```bash
   npm install
   npm run compile:sass
   ```

## Usage
- Open `http://127.0.0.1:8000/` in your browser.
- Select encryption algorithm (AES, 3DES, OTP).
- Choose the encryption mode (ECB, CBC, CFB, CTR).
- Enter plaintext or ciphertext for encryption/decryption.
- Submit to get results in real-time without reloading.

## Contributing
If you’d like to contribute:
- Fork the repository.
- Create a new branch.
- Make your changes and submit a pull request.

## License
This project is licensed under the MIT License.

## Author
- **Nasir A. Degu**  
- Contact: [nasir.adem@outlook.com](mailto:nasir.adem@outlook.com)
