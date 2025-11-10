# Invisible Ink

'*Invisible Ink*' is a steganography web application that lets you hide fully encrypted notes inside everyday images. This is another one of my personal university projects that I am able to showcase. This application showcases practical crypto + front-end skills.

## Why I Built It
- To develop a further understanding of encryption/decryption models (AES-256-GCM in this case)
- Learn about image processing, specifically steganography

## What Features Does It Have
- Client-side **AES-256-GCM** encryption with salted PBKDF2 key derivation (~250k iterations)
- Least significant bit (LSB) **steganography**
- Animated toggle to switch between Encryption and Decryption
- Image previews upon loading in an image
- Custom output filename + type for encoded images
- **Error handling** that catches bad keys, oversized messages, and corrupted payloads

## Process Of How It Works

1. **Key Derivation** – PBKDF2 turns the user keycode into a 256-bit AES key using a random salt
2. **Encryption** – AES‑GCM with a random IV encrypts the message; we stash salt, IV, lengths, etc. in a binary payload
3. **Embedding** – Each payload bit replaces the LSB of R/G/B channels across the cover image
4. **Decryption** – Reverse the LSB walk to recover the payload, re-derive the key with the salt, decrypt via AES‑GCM

## Tech Stack
- **Frontend:** HTML5, CSS, JavaScript
- **APIs/Libraries:** Web Crypto API, Canvas API, File API, createImageBitmap, URL.createObjectURL

## Running Locally

1. Clone or download the repo.
2. Option A: double-click `index.html`. Modern browsers allow file:// usage.
3. Option B: serve it (makes debugging nicer):
   ```bash
   # Python 3
   cd "Invisible Ink"
   python -m http.server 8000
   ```
   Then open http://localhost:8000.

## Tips for Testing

- Try a larger image if you see a “Message is too long for this image” warning.
- Use a predictable short key like `12345` to sanity-check the flow before trusting real secrets.
- JPEG/WebP re-export from other tools can destroy LSB data. Share the generated file as-is!

## Security Notes

- Cryptography happens entirely in the browser via the Web Crypto API.
- Keycodes never leave the client; there’s no backend.
- Steganography capacity is linear: more pixels = more hidden bytes. Don’t try to squeeze novels into tiny PNGs.
