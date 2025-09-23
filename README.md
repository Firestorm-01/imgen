Image Encryption + Steganography
================================

This project encrypts a secret image with AES-GCM and hides the encrypted bytes in the least-significant bits of a cover image. You can use it via a CLI or a small Flask server + HTML UI.

Requirements
------------
- Python 3.10+
- Install deps:

```
pip install -r requirements.txt
```

CLI Usage
---------
The CLI is implemented in `steganography.py`.

- Hide a secret image into a cover image:

```
python steganography.py hide secret1.jpg cover.jpg stego1.png MyStrongPassword123
```

- Extract the secret image from the stego image:

```
python steganography.py extract stego1.png MyStrongPassword123 secret_out.jpg
```

Notes
- The cover image must be large enough to hold the payload. Rule of thumb: width * height * 3 bits must exceed 8 * (overhead + secret bytes). Overhead is ~4 + 16 + 12 + 16 + 4 bytes.
- PNG is recommended for the stego output to avoid lossy compression.

Server + Web UI
---------------

1) Start the Flask server:

```
python app.py
```

2) Open `index.html` in your browser. The page assumes the server runs on http://127.0.0.1:5000.

Troubleshooting
---------------
- If extraction fails with wrong password or corrupted data, you will see an error. Re-check the password and ensure the cover image was not recompressed.
- On Windows, if `python` maps to Python 2, use `py -3` instead of `python`.

