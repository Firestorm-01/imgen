# app.py
import io
import os
import tempfile
import threading
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import the functions from the steganography module
from steganography import (
    encrypt_image,
    hide_bytes_in_image,
    extract_bytes_from_image,
    decrypt_image,
    parse_decrypted_payload,
)


def _cleanup_file_later(path: str, delay: float = 5.0):
    """Remove a file after `delay` seconds in a background thread.

    This avoids leaving temporary files behind after send_file returns.
    """

    def _remove():
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            # Best-effort removal; don't crash the app if it fails
            pass

    t = threading.Timer(delay, _remove)
    t.daemon = True
    t.start()


app = Flask(__name__)
CORS(app)

# Use a secure temporary directory for uploads at runtime
RUNTIME_TMP = tempfile.mkdtemp(prefix="imgen_")
app.config["UPLOAD_FOLDER"] = RUNTIME_TMP

# Limit uploads to a reasonable size (here ~20 MB). Adjust as needed.
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024


@app.route("/hide", methods=["POST"])
def hide_image_endpoint():
    if "secret" not in request.files or "cover" not in request.files:
        return jsonify({"error": "Missing secret or cover image file"}), 400
    if "password" not in request.form:
        return jsonify({"error": "Missing password"}), 400

    secret_file = request.files["secret"]
    cover_file = request.files["cover"]
    password = request.form["password"]

    secret_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(secret_file.filename))
    cover_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(cover_file.filename))
    secret_file.save(secret_path)
    cover_file.save(cover_path)

    # Use a unique temporary file for the output to avoid collisions when
    # multiple requests are processed concurrently.
    tf = tempfile.NamedTemporaryFile(prefix="stego_", suffix=".png", dir=app.config["UPLOAD_FOLDER"], delete=False)
    output_path = tf.name
    tf.close()

    try:
        encrypted_bytes = encrypt_image(secret_path, password)
        hide_bytes_in_image(cover_path, encrypted_bytes, output_path)
        # Ensure the file was written and send its bytes back to the client
        try:
            with open(output_path, "rb") as f:
                file_bytes = f.read()
        except Exception:
            # If we can't read the generated file, return an error
            for p in (secret_path, cover_path, output_path):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except Exception:
                    pass
            return jsonify({"error": "Failed to generate stego image."}), 500

        if not file_bytes:
            # Prevent returning an empty file to clients
            for p in (secret_path, cover_path, output_path):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except Exception:
                    pass
            return jsonify({"error": "Generated stego image is empty."}), 500

        # Schedule cleanup of the temporary files shortly after returning
        _cleanup_file_later(secret_path, delay=5.0)
        _cleanup_file_later(cover_path, delay=5.0)
        _cleanup_file_later(output_path, delay=15.0)

        # Send the generated stego image from memory to avoid race conditions
        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=True,
            download_name="stego_image.png",
            mimetype="image/png",
        )
    except ValueError as e:
        # Validation errors (e.g., cover too small)
        # Clean up immediately
        for p in (secret_path, cover_path, output_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        # Unexpected errors: clean up and return a JSON error so the client
        # doesn't receive an empty response body.
        for p in (secret_path, cover_path, output_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        return jsonify({"error": "Internal server error while hiding image."}), 500


@app.route("/extract", methods=["POST"])
def extract_image_endpoint():
    if "stego" not in request.files:
        return jsonify({"error": "Missing stego image file"}), 400
    if "password" not in request.form:
        return jsonify({"error": "Missing password"}), 400

    stego_file = request.files["stego"]
    password = request.form["password"]

    stego_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(stego_file.filename))
    stego_file.save(stego_path)

    try:
        encrypted_bytes = extract_bytes_from_image(stego_path)
        decrypted_bytes = decrypt_image(encrypted_bytes, password)

        # Schedule cleanup of the uploaded stego file
        _cleanup_file_later(stego_path, delay=5.0)

        if not decrypted_bytes:
            try:
                if os.path.exists(stego_path):
                    os.remove(stego_path)
            except Exception:
                pass
            return jsonify({"error": "Decrypted payload is empty."}), 400

        # Parse payload to get original filename and bytes
        try:
            orig_name, file_bytes = parse_decrypted_payload(decrypted_bytes)
        except Exception:
            # Fallback: treat decrypted_bytes as raw image bytes
            orig_name = "extracted_secret"
            file_bytes = decrypted_bytes

        # Guess a mimetype from filename extension
        import mimetypes
        mimetype, _ = mimetypes.guess_type(orig_name)
        if not mimetype:
            mimetype = "application/octet-stream"

        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=True,
            download_name=orig_name,
            mimetype=mimetype,
        )

    except ValueError as e:
        try:
            if os.path.exists(stego_path):
                os.remove(stego_path)
        except Exception:
            pass
        return jsonify({"error": str(e)}), 400
    except Exception:
        # We don't reveal detailed crypto errors to clients in production
        try:
            if os.path.exists(stego_path):
                os.remove(stego_path)
        except Exception:
            pass
        return jsonify({"error": "Failed to extract. Check password or file integrity."}), 400


if __name__ == "__main__":
    # For production use a proper WSGI server (gunicorn/uWSGI).
    # The debug server should not be used in production.
    app.run(host="0.0.0.0", debug=False)