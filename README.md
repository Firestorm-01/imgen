
Image Encryption + Steganography
================================

This repository provides two ways to use the steganography tool:

- A CLI implemented in `steganography.py`.
- A small Flask server + browser UI (`app.py` + `index.html`).

Quick start
-----------

1. Create a virtual environment and install dependencies:

	pip install -r requirements.txt

2. Run the Flask app for local testing (not for production):

	python app.py

3. Open `index.html` in your browser and use the web UI (it expects the server at http://127.0.0.1:5000).

CLI examples
------------

Hide a secret image into a cover image (recommended stego output: PNG):

	python steganography.py hide secret.png --cover cover.png stego.png MyStrongPassword123

Extract a secret image from a stego image:

	python steganography.py extract stego.png MyStrongPassword123 secret_out.png

Production notes
----------------

- The Flask development server is not suitable for production. Use a WSGI server like gunicorn:

	gunicorn -w 4 -b 0.0.0.0:8000 app:app

- Protect the server behind HTTPS and add authentication if exposing it to the internet.
- Temporary files are written to a secure temp directory at runtime. The app schedules best-effort cleanup.

Repository cleanup
-----------------

The repository previously contained example images used for development. To fully remove them from Git history and the working tree you can run the included `cleanup_repo.sh` script (it will remove example image files and perform `git rm`).

If you only want to keep the code but not the binary sample images, run locally:

	./cleanup_repo.sh

This operation modifies your working tree (and commits) — review the script before running.

Running tests / smoke test
--------------------------

This project includes a small `smoke_test.py` which exercises the core encrypt/hide/extract/decrypt flow. To run it safely:

1. Create and activate a virtual environment:

	python3 -m venv .venv
	source .venv/bin/activate

2. Install dependencies:

	pip install -r requirements.txt

3. Run the smoke test:

	python smoke_test.py

If you cannot create a venv (e.g., restricted environment), run the steps in a machine where you can manage packages.

