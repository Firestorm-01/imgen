# app.py
import io
import os
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import the functions from your original script
from steganography import encrypt_image, hide_bytes_in_image, \
                          extract_bytes_from_image, decrypt_image

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Create a temporary folder for uploads
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/hide', methods=['POST'])
def hide_image_endpoint():
    # 1. Check if files and password are in the request
    if 'secret' not in request.files or 'cover' not in request.files:
        return jsonify({"error": "Missing secret or cover image file"}), 400
    if 'password' not in request.form:
        return jsonify({"error": "Missing password"}), 400

    secret_file = request.files['secret']
    cover_file = request.files['cover']
    password = request.form['password']

    # 2. Securely save the uploaded files temporarily
    secret_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(secret_file.filename))
    cover_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cover_file.filename))
    secret_file.save(secret_path)
    cover_file.save(cover_path)

    try:
        # 3. Use your original functions
        encrypted_bytes = encrypt_image(secret_path, password)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], "stego_image.png")
        hide_bytes_in_image(cover_path, encrypted_bytes, output_path)

        # 4. Send the resulting image back to the user
        return send_file(
            output_path,
            as_attachment=True,
            download_name='stego_image.png',
            mimetype='image/png'
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    finally:
        # 5. Clean up the temporary files
        if os.path.exists(secret_path): os.remove(secret_path)
        if os.path.exists(cover_path): os.remove(cover_path)
        # We don't remove output_path here because send_file needs it.
        # A more robust app would clean these up later.

@app.route('/extract', methods=['POST'])
def extract_image_endpoint():
    # 1. Check for file and password
    if 'stego' not in request.files:
        return jsonify({"error": "Missing stego image file"}), 400
    if 'password' not in request.form:
        return jsonify({"error": "Missing password"}), 400

    stego_file = request.files['stego']
    password = request.form['password']

    # 2. Save file temporarily
    stego_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(stego_file.filename))
    stego_file.save(stego_path)

    try:
        # 3. Use your original functions
        encrypted_bytes = extract_bytes_from_image(stego_path)
        decrypted_bytes = decrypt_image(encrypted_bytes, password)

        # 4. Send the decrypted image data back
        # We use io.BytesIO because the data is in memory, not a file on disk
        return send_file(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            download_name='extracted_secret.png', # You might need to adjust the extension
            mimetype='image/png'
        )
    except Exception as e:
        # Catch potential errors from decryption (e.g., wrong password)
        return jsonify({"error": "Failed to extract. Check password or file integrity."}), 400
    finally:
        # 5. Clean up
        if os.path.exists(stego_path): os.remove(stego_path)


if __name__ == '__main__':
    # Your original main() is no longer needed to run the server
    # Run the Flask app
    app.run(debug=True)