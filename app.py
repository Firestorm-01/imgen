import io
import os
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Assuming your steganography.py module is in the same directory
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
    if 'secret' not in request.files or 'password' not in request.form:
        return jsonify({"error": "Missing secret image or password"}), 400

    secret_file = request.files['secret']
    password = request.form['password']
    use_stego = request.form.get('use_stego') # Check for the stego flag

    # 2. Securely save the uploaded secret file temporarily
    secret_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(secret_file.filename))
    secret_file.save(secret_path)

    try:
        # 3. Encrypt the secret image data first, regardless of stego
        encrypted_bytes = encrypt_image(secret_path, password)
        
        # 4. Handle steganography option
        if use_stego and 'cover' in request.files:
            cover_file = request.files['cover']
            cover_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cover_file.filename))
            cover_file.save(cover_path)
            
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], "stego_image.png")
            hide_bytes_in_image(cover_path, encrypted_bytes, output_path)
            
            # Send the resulting stego image
            return send_file(
                output_path,
                as_attachment=True,
                download_name='stego_image.png',
                mimetype='image/png'
            )
        else:
            # No steganography, just send the encrypted file
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], "secret.enc")
            with open(output_path, "wb") as f:
                f.write(encrypted_bytes)
            
            # Send the resulting encrypted file
            return send_file(
                output_path,
                as_attachment=True,
                download_name='secret.enc',
                mimetype='application/octet-stream' # Generic binary file type
            )
            
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    finally:
        # 5. Clean up the temporary files
        if os.path.exists(secret_path): os.remove(secret_path)
        if 'cover_path' in locals() and os.path.exists(cover_path): os.remove(cover_path)
        # Note: A more robust app would clean up output_path after sending.

@app.route('/extract', methods=['POST'])
def extract_image_endpoint():
    # 1. Check for file and password
    if 'input_file' not in request.files:
        return jsonify({"error": "Missing input file"}), 400
    if 'password' not in request.form:
        return jsonify({"error": "Missing password"}), 400

    input_file = request.files['input_file']
    password = request.form['password']
    is_stego = request.form.get('is_stego') # Check for the stego flag

    # 2. Save file temporarily
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(input_file.filename))
    input_file.save(input_path)

    try:
        # 3. Use your original functions based on the stego flag
        if is_stego:
            encrypted_bytes = extract_bytes_from_image(input_path)
        else:
            with open(input_path, "rb") as f:
                # Read the 4-byte header and then the rest of the data
                length_bytes = f.read(4)
                if len(length_bytes) < 4:
                     raise ValueError("Encrypted data is too short to read header.")
                encrypted_bytes = f.read()
        
        # 4. Decrypt the data
        decrypted_bytes = decrypt_image(encrypted_bytes, password)

        # 5. Send the decrypted image data back
        return send_file(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            download_name='extracted_secret.png',
            mimetype='image/png'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to extract. Check password or file integrity. Error: {e}"}), 400
    finally:
        # 6. Clean up
        if os.path.exists(input_path): os.remove(input_path)

if __name__ == '__main__':
    app.run(debug=True)
