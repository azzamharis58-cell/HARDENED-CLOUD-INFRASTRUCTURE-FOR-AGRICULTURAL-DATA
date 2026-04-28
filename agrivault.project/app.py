"""
AgriVault - Flask Web Server
Hardened Cloud Infrastructure for Agriculture Data
RESTful API backend for the web portal
"""

from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
import os
import json
import time
import uuid
import threading
from werkzeug.utils import secure_filename
from crypto_engine import encrypt_file, decrypt_file, get_file_metadata

app = Flask(__name__)
CORS(app)

# ── Configuration ──────────────────────────────────────────────────────────────
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted_vault"
DECRYPTED_FOLDER = "decrypted_temp"
METADATA_FILE = "vault_metadata.json"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Create directories
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Thread lock for metadata file access
metadata_lock = threading.Lock()


# ── Metadata helpers ───────────────────────────────────────────────────────────
def load_metadata() -> dict:
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            return json.load(f)
    return {"files": []}


def save_metadata(data: dict):
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
def upload_and_encrypt():
    """Receive a file and password, encrypt it, store in vault."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    if "password" not in request.form:
        return jsonify({"error": "No password provided"}), 400

    file = request.files["file"]
    password = request.form["password"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    safe_name = secure_filename(file.filename)
    temp_path = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(temp_path)

    try:
        result = encrypt_file(temp_path, password)

        file_id = str(uuid.uuid4())
        enc_dest = os.path.join(ENCRYPTED_FOLDER, file_id + ".agv")
        os.rename(result["encrypted_path"], enc_dest)
        os.remove(temp_path)

        entry = {
            "id": file_id,
            "original_filename": result["original_filename"],
            "original_size": result["original_size"],
            "encrypted_size": result["encrypted_size"],
            "encrypted_path": enc_dest,
            "algorithm": result["algorithm"],
            "kdf": result["kdf"],
            "integrity": result["integrity"],
            "uploaded_at": result["timestamp"],
            "status": "encrypted"
        }

        with metadata_lock:
            meta = load_metadata()
            meta["files"].append(entry)
            save_metadata(meta)

        return jsonify({
            "success": True,
            "file_id": file_id,
            "filename": result["original_filename"],
            "original_size": result["original_size"],
            "encrypted_size": result["encrypted_size"],
            "algorithm": result["algorithm"],
            "message": "File encrypted and stored securely."
        })

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500


@app.route("/api/files", methods=["GET"])
def list_files():
    """Return all files in the vault (metadata only, no content)."""
    with metadata_lock:
        meta = load_metadata()
    files = []
    for f in meta["files"]:
        files.append({
            "id": f["id"],
            "original_filename": f["original_filename"],
            "original_size": f["original_size"],
            "encrypted_size": f["encrypted_size"],
            "algorithm": f["algorithm"],
            "uploaded_at": f["uploaded_at"],
            "status": f["status"]
        })
    return jsonify({"files": files, "count": len(files)})


@app.route("/api/download/<file_id>", methods=["POST"])
def download_and_decrypt(file_id):
    """Decrypt a vault file and send it to the client."""
    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "Password required"}), 400

    with metadata_lock:
        meta = load_metadata()

    entry = next((f for f in meta["files"] if f["id"] == file_id), None)
    if not entry:
        return jsonify({"error": "File not found"}), 404

    try:
        result = decrypt_file(
            entry["encrypted_path"],
            data["password"],
            output_dir=DECRYPTED_FOLDER
        )
        return send_file(
            result["decrypted_path"],
            as_attachment=True,
            download_name=result["original_filename"]
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


@app.route("/api/delete/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    """Securely delete an encrypted file from the vault."""
    with metadata_lock:
        meta = load_metadata()
        entry = next((f for f in meta["files"] if f["id"] == file_id), None)
        if not entry:
            return jsonify({"error": "File not found"}), 404

        # Secure delete: overwrite before removing
        try:
            if os.path.exists(entry["encrypted_path"]):
                size = os.path.getsize(entry["encrypted_path"])
                with open(entry["encrypted_path"], "r+b") as f:
                    f.write(os.urandom(size))
                os.remove(entry["encrypted_path"])
        except Exception as e:
            return jsonify({"error": f"Deletion failed: {str(e)}"}), 500

        meta["files"] = [f for f in meta["files"] if f["id"] != file_id]
        save_metadata(meta)

    return jsonify({"success": True, "message": "File securely deleted."})


@app.route("/api/stats", methods=["GET"])
def vault_stats():
    """Return summary statistics about the vault."""
    with metadata_lock:
        meta = load_metadata()

    files = meta["files"]
    total_original = sum(f["original_size"] for f in files)
    total_encrypted = sum(f["encrypted_size"] for f in files)

    return jsonify({
        "total_files": len(files),
        "total_original_bytes": total_original,
        "total_encrypted_bytes": total_encrypted,
        "vault_overhead_bytes": total_encrypted - total_original
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AgriVault API", "version": "1.0.0"})


if __name__ == "__main__":
    print("=" * 60)
    print("  AgriVault - Hardened Agriculture Data Encryption Portal")
    print("  Running on http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
