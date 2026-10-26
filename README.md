# Secure Data

## About the Project
Secure Data is a web application developed using Flask to demonstrate data processing at the Presentation Layer of the OSI model.

## Features
- **Base64 Encoding:** Converts the input message into Base64 format.
- **AES Encryption:** Encrypts the encoded message using AES.
- **SHA-256 Hashing:** Generates a hash to demonstrate data integrity.

## Technologies Used
- Python
- Flask
- HTML
- CSS
- JavaScript

## How to Run

1. Install Python on your computer.
2. Install Flask:

   ```bash
   pip install flask
   ```

3. Open the project folder in the terminal.
4. Run the application:

   ```bash
   python app.py
   ```

5. Open the URL shown in the terminal in your web browser (usually `http://127.0.0.1:5000`).

## Project Structure

```text
Secure-Data/
├── app.py
├── static/
│   └── style.css
├── templates/
│   └── index.html
└── README.md
```

## Purpose
This project demonstrates encoding, encryption, and hashing through a simple web interface.
