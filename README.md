![Logo](./static/logo.png)
# Cryptix-Q

## Overview
The Cryptix-Q is a Flask-based web application that leverages lattice-based cryptography to encrypt files. The system uses advanced cryptographic techniques, integrates with blockchain (Ganache), and provides a user-friendly interface for secure file encryption and storage.

## Features
- **Lattice-Based Cryptography:** Uses lattice parameters for robust encryption.
- **File Encryption:** Convert file contents into bits, encrypt using lattice-based techniques, and securely store them.
- **Blockchain Integration:** Save encrypted data on a blockchain network (Ganache).
- **User Authentication:** Secure login system for authorized users.
- **Web Interface:** Simple and clean UI for file encryption and transaction management.

## Technologies Used
- **Backend:** Python (Flask framework)
- **Frontend:** HTML, CSS
- **Cryptography:** Lattice-based cryptography
- **Blockchain:** Ganache with Web3.py
- **Environment Management:** `dotenv` for environment variable management
- **Deployment:** Local development with Flask

## Setup Instructions
### Prerequisites
- Python 3.7+
- Node.js (for Ganache CLI)
- Ganache CLI or Ganache GUI
- `pipenv` or `pip` for Python package management

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>

# Install dependencies:

```bash
pip install -r requirements.txt

```
# Setting Up a `.env` File

Create a `.env` file in the root directory of your project and include the following variables:

```makefile
SECRET_KEY=your_secret_key
GANACHE_URL=http://127.0.0.1:7545
ADMIN_USERNAME=admin
ADMIN_PASSWORD=password123
PRIVATE_KEY=<your_ethereum_private_key>
```

# Important:

Replace your_secret_key and <your_ethereum_private_key> with your actual secret key and Ethereum private key, respectively. Ensure this file is not shared or pushed to version control for security reasons

1. **Start Ganache on your local machine.**

2. **Run the application:**

   ```bash
   python app.py
   ```

## File Structure

```bash
project/
├── app.py                # Flask application
├── static/
│   └── styles.css        # Stylesheet for the web interface
├── templates/
│   ├── index.html        # Home page
│   ├── login.html        # Login page
│   ├── encrypt.html      # Encryption page
├── uploads/              # Folder for uploaded and encrypted files
├── .env                  # Environment variables
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

## Usage

### Login
- Use the `ADMIN_USERNAME` and `ADMIN_PASSWORD` from the `.env` file.

### Encrypt File
- Upload a file through the "Encrypt File" page.
- The file is encrypted and saved locally in the `uploads` folder.

### Download Encrypted File
- Access encrypted files through the "Download" page.

### Blockchain Transaction
- Encrypted data is stored on the blockchain for additional security.

## Security Notes

### Private Key
- Store your private key securely in the `.env` file.

### Authentication
- Change default admin credentials after setup.

### Encryption
- The project uses lattice-based cryptography for enhanced security.

## Future Enhancements

- Implement multi-user support with role-based access.
- Add decryption functionality.
- Integrate with a distributed file system (e.g., IPFS) for better scalability.

## Credits

This project was developed as a demonstration of lattice-based cryptography, blockchain integration, and secure file handling using Flask.
