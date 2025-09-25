from flask import Flask, request, send_file, render_template
from werkzeug.utils import secure_filename
import os
from io import BytesIO
from steganography import encrypt_image, hide_bytes_in_image, extract_bytes_from_image, decrypt_image

app = Flask(__name__)
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')  # Save your HTML as templates/index.html

@app.route('/hide', methods=['POST'])
def hide():
    use_stego = 'use_stego' in request.form
    password = request.form['password'].encode()

    secret_file = request.files.get('secret')
    secret_bytes = secret_file.read()

    if use_stego:
        cover_file = request.files.get('cover')
        cover_bytes = cover_file.read()
        # Encrypt secret first
        encrypted_bytes = encrypt_image(secret_bytes, password)
        # Hide inside cover
        output_bytes = hide_bytes_in_image(cover_bytes, encrypted_bytes)
        output_filename = 'stego_image.png'
    else:
        output_bytes = encrypt_image(secret_bytes, password)
        output_filename = 'secret.enc'

    return send_file(BytesIO(output_bytes), download_name=output_filename, as_attachment=True)

@app.route('/extract', methods=['POST'])
def extract():
    password = request.form['password'].encode()
    is_stego = 'is_stego' in request.form

    input_file = request.files.get('input_file')
    input_bytes = input_file.read()

    if is_stego:
        extracted_bytes = extract_bytes_from_image(input_bytes)
        decrypted_bytes = decrypt_image(extracted_bytes, password)
    else:
        decrypted_bytes = decrypt_image(input_bytes, password)

    return send_file(BytesIO(decrypted_bytes), download_name='extracted_secret.png', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
