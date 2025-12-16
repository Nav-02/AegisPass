AegisPass 🛡️

A Secure, Offline, Zero-Knowledge Password Manager

AegisPass is a desktop password manager built with Python and PyQt6 that prioritizes user control and security. Unlike cloud-based solutions, AegisPass functions entirely offline, using military-grade encryption to ensure that your credentials never leave your device.

🚀 Core Philosophy

Zero-Knowledge: The application never stores or transmits your master password.

Offline-First: You own your data. The vault is stored as an encrypted local file.

Resilient: Includes automated atomic backups to prevent data loss or corruption.

✨ Key Features

Dual-Lock Architecture (Key Wrapping):

Access your vault using your Master Password (Primary).

Recover access using a generated Emergency Recovery Key if you forget your password.

Uses envelope encryption to support multiple access methods without duplicating data.

Military-Grade Security:

AES-256 GCM (Galois/Counter Mode) for authenticated encryption.

PBKDF2-HMAC-SHA256 with 600,000 iterations for key derivation.

Unique salts and nonces for every operation to prevent rainbow table and replay attacks.

Atomic Backups:

Automatically creates a timestamped backup of your vault before every save operation to protect against file corruption or sabotage.

Emergency Kit Generator:

Automatically generates a PDF Recovery Kit containing your secure key during setup.

🛠️ Tech Stack

Language: Python 3.10+

GUI Framework: PyQt6 (Native Desktop Interface)

Cryptography: cryptography library (OpenSSL bindings via Hazmat primitives)

Utilities: fpdf2 (PDF Generation), json (Data Structure)

📦 Installation

Clone the repository:

git clone https://github.com/Nav-02/AegisPass.git
cd AegisPass


Install dependencies:

pip install PyQt6 cryptography fpdf2


Run the application:

python main.py


🔐 Security Architecture

AegisPass implements a robust Model-View-Controller (MVC) design pattern, isolating the security logic (aegis.py) from the user interface (main.py).

Encryption Workflow

Key Generation: A random 256-bit Data Encryption Key (DEK) is generated. This key encrypts the actual vault data.

Key Wrapping: The DEK is encrypted twice:

Slot 1: Encrypted with a key derived from the user's Master Password + Questionnaire.

Slot 2: Encrypted with a key derived from the random Recovery Key.

Storage: The vault file (.json) stores these encrypted slots alongside the encrypted data payload.

Anti-Tamper Mechanism

The application uses Authenticated Encryption (GCM). If a malicious actor modifies the encrypted file (even a single bit), the authentication tag check will fail, and the application will refuse to load the corrupted data, preventing tampering attacks.

📂 Project Structure

main.py: The Frontend. Handles the PyQt6 UI, event loops, and user interactions.

aegis.py: The Backend. Contains the Aegis class which handles all cryptographic operations, key derivation, and file I/O logic.

⚠️ Disclaimer

This is a personal project created for educational and portfolio purposes. While it uses industry-standard cryptographic primitives, it has not undergone a third-party security audit. Use at your own risk for critical data.
