from steganography import encrypt_image, hide_bytes_in_image, extract_bytes_from_image, decrypt_image
from pathlib import Path
import os

# Simple smoke test that doesn't require specific repo images.
# It will create a small dummy PNG as cover and a tiny payload file as secret.

from PIL import Image

def make_cover(path: str, size=(64,64)):
    img = Image.new('RGB', size, color=(123, 231, 45))
    img.save(path)


def main():
    tmp = Path('temp_uploads')
    tmp.mkdir(exist_ok=True)
    cover_path = tmp / 'cover_smoke.png'
    secret_path = tmp / 'secret_smoke.jpg'
    stego_path = tmp / 'stego_smoke.png'

    # Prepare files
    make_cover(str(cover_path))
    # Create a small JPEG as the secret to ensure support for JPEG secrets
    from PIL import Image
    secret_img = Image.new('RGB', (8,8), color=(10,20,30))
    secret_img.save(secret_path, format='JPEG')

    password = 'test-pass-123'

    # Encrypt and hide
    enc = encrypt_image(str(secret_path), password)
    hide_bytes_in_image(str(cover_path), enc, str(stego_path))

    # Extract and decrypt
    enc2 = extract_bytes_from_image(str(stego_path))
    out = decrypt_image(enc2, password)

    # Parse the decrypted payload header: 2-byte filename len + filename + bytes
    fname_len = int.from_bytes(out[:2], 'big')
    fname = out[2:2+fname_len].decode('utf-8')
    file_bytes = out[2+fname_len:]

    assert fname == 'secret_smoke.jpg', f'Filename mismatch: {fname}'
    assert file_bytes, 'Decrypted file bytes empty'
    print('SMOKE TEST PASS')

if __name__ == '__main__':
    main()
