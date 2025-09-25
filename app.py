from flask import Flask, request, send_file, render_template
import os
import tempfile
from io import BytesIO
from steganography import (
    encrypt_image,
    hide_bytes_in_image,
    extract_bytes_from_image,
    decrypt_image,
    parse_decrypted_payload
)
from PIL import Image

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/hide', methods=['POST'])
def hide():
    use_stego = 'use_stego' in request.form
    password = request.form['password']

    secret_file = request.files.get('secret')

    # Save secret to temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_secret:
        secret_path = tmp_secret.name
        secret_file.save(secret_path)

    try:
        if use_stego:
            cover_file = request.files.get('cover')
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_cover:
                cover_path = tmp_cover.name
                cover_file.save(cover_path)

            encrypted_bytes = encrypt_image(secret_path, password)

            # Temp output for stego image
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_out:
                output_path = tmp_out.name

            hide_bytes_in_image(cover_path, encrypted_bytes, output_path)
            return send_file(output_path, download_name='stego_image.png', as_attachment=True)
        else:
            encrypted_bytes = encrypt_image(secret_path, password)
            return send_file(
                BytesIO(encrypted_bytes),
                download_name='secret.enc',
                as_attachment=True
            )
    finally:
        os.remove(secret_path)
        if use_stego:
            os.remove(cover_path)
            os.remove(output_path)


@app.route('/extract', methods=['POST'])
def extract():
    password = request.form['password']
    is_stego = 'is_stego' in request.form

    input_file = request.files.get('input_file')
    input_bytes = input_file.read()

    if is_stego:
        # Wrap bytes in BytesIO so PIL can read it
        encrypted_bytes = extract_bytes_from_image(BytesIO(input_bytes))
    else:
        encrypted_bytes = input_bytes

    decrypted_bytes = decrypt_image(encrypted_bytes, password)
    filename, file_bytes = parse_decrypted_payload(decrypted_bytes)

    # Save to temp file and send
    _, ext = os.path.splitext(filename)
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_output:
        temp_output.write(file_bytes)
        temp_path = temp_output.name

    return send_file(temp_path, download_name=filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
