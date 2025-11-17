from flask import Flask, request, jsonify, send_file, render_template, session
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import NoCredentialsError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from braket.circuits import Circuit
from braket.devices import LocalSimulator
from flask_session import Session
import io
from dotenv import load_dotenv
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Flask-Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

load_dotenv()  # Load environment variables from .env

# AWS S3 Configuration
S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY")

s3_client = boto3.client(
    's3',
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name=S3_REGION
)

# Helper functions for S3
def upload_to_s3(file, bucket_name, object_name):
    try:
        s3_client.upload_fileobj(file, bucket_name, object_name)
    except NoCredentialsError:
        raise Exception("S3 credentials not provided or invalid.")

def download_from_s3(bucket_name, object_name):
    try:
        file_stream = io.BytesIO()
        s3_client.download_fileobj(bucket_name, object_name, file_stream)
        file_stream.seek(0)
        return file_stream
    except Exception as e:
        raise Exception(f"Error downloading file: {str(e)}")

# Step 1: MDI-QKD Simulation
def mdi_qkd_simulation():
    device = LocalSimulator()
    alice_circuit = Circuit().h(0).rx(0, 1.57)
    bob_circuit = Circuit().h(1).rx(1, 1.57)
    charlie_circuit = Circuit().cnot(0, 1).h(0).measure(0).measure(1)

    result_alice = device.run(alice_circuit, shots=1000).result()
    result_charlie = device.run(charlie_circuit, shots=1000).result()

    key_alice = "".join(str(bit) for bit in result_alice.measurement_counts.keys())
    key_charlie = "".join(str(bit) for bit in result_charlie.measurement_counts.keys())
    shared_key = key_alice[:len(key_charlie)]
    return shared_key

# Step 2: PQC Encryption and Decryption
def pqc_encryption(shared_key, plaintext):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'QKD Key Expansion',
        backend=default_backend()
    )
    symmetric_key = kdf.derive(shared_key.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return ciphertext, iv, encrypted_symmetric_key, private_key

def pqc_decryption(private_key, encrypted_symmetric_key, iv, ciphertext):
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Routes
@app.route('/')
def index():
    if 'files' not in session:
        session['files'] = []
    file_list = session.get('files', [])
    return render_template('index.html', files=file_list)

@app.route('/files', methods=['GET'])
def get_files():
    try:
        file_list = session.get('files', [])
        return jsonify({"files": file_list})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch file list: {str(e)}"}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    plaintext = file.read()

    # Simulate MDI-QKD and encrypt the file
    shared_key = mdi_qkd_simulation()
    ciphertext, iv, encrypted_symmetric_key, private_key = pqc_encryption(shared_key, plaintext)

    # Create file-like objects for encrypted data and keys
    encrypted_data = io.BytesIO(iv + ciphertext)
    private_key_data = io.BytesIO(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_data = io.BytesIO(encrypted_symmetric_key)

    # Upload to S3: Create separate copies for upload to avoid closing the original streams
    upload_to_s3(io.BytesIO(iv + ciphertext), S3_BUCKET, f"encrypted/{filename}.enc")
    upload_to_s3(io.BytesIO(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )), S3_BUCKET, f"keys/{filename}.key")
    upload_to_s3(io.BytesIO(encrypted_symmetric_key), S3_BUCKET, f"keys/{filename}.symkey")

    # Update session with uploaded filename
    files = session.get('files', [])
    files.append(filename)
    session['files'] = files

    # Send the key file directly to the client
    key_data.seek(0)  # Reset the file pointer for sending
    return send_file(
        key_data,
        as_attachment=True,
        download_name=f"{filename}.symkey",
        mimetype="application/octet-stream"
    )

@app.route('/retrieve', methods=['POST'])
def retrieve_file():
    filename = request.form.get('filename')
    uploaded_key = request.files.get('key')

    if not filename or not uploaded_key:
        return jsonify({"error": "Filename and key file must be provided"}), 400

    uploaded_key_content = uploaded_key.read()

    try:
        encrypted_data = download_from_s3(S3_BUCKET, f"encrypted/{filename}.enc")
        private_key_data = download_from_s3(S3_BUCKET, f"keys/{filename}.key")
        key_data = download_from_s3(S3_BUCKET, f"keys/{filename}.symkey")
    except Exception as e:
        return jsonify({"error": f"File retrieval error: {str(e)}"}), 500

    if uploaded_key_content != key_data.read():
        return jsonify({"error": "Invalid key file"}), 403

    private_key = serialization.load_pem_private_key(
        private_key_data.read(),
        password=None,
        backend=default_backend()
    )

    iv = encrypted_data.read(16)
    ciphertext = encrypted_data.read()
    plaintext = pqc_decryption(private_key, uploaded_key_content, iv, ciphertext)

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream"
    )

if __name__ == '__main__':
    app.run(debug=True)
