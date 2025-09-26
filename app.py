from flask import Flask, render_template, request, redirect, send_file
import os
import cv2
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import numpy as np
from secretsharing import SecretSharer
import secrets

import pickle  # For saving dimensions
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, session, flash


app = Flask(__name__)

app.secret_key = secrets.token_hex(16)  # For session and flash messages

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SHARES_FOLDER'] = 'shares'
app.config['DECRYPTED_FOLDER'] = 'decrypted'

# Ensure necessary folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SHARES_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECRYPTED_FOLDER'], exist_ok=True)

# Encryption key generation (this is the secret we will split)
key = Fernet.generate_key()
cipher_suite = Fernet(key)


users = {}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists')
            return redirect(url_for('register'))
        users[username] = generate_password_hash(password)
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_hash = users.get(username)
        
        if user_hash and check_password_hash(user_hash, password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
        
    return render_template('login.html')


@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_video():
    if 'video' not in request.files or 'watermark' not in request.files:
        return redirect('/')
    
    video_file = request.files['video']
    watermark_file = request.files['watermark']

    if video_file.filename == '' or watermark_file.filename == '':
        return redirect('/')
    
    video_filename = secure_filename(video_file.filename)
    watermark_filename = secure_filename(watermark_file.filename)

    video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)
    watermark_filepath = os.path.join(app.config['UPLOAD_FOLDER'], watermark_filename)
    
    video_file.save(video_filepath)
    watermark_file.save(watermark_filepath)

    # Encrypt video and embed watermark, then save key shares
    process_video(video_filepath, watermark_filepath)

    # Redirect to reconstruction with the video filename as a parameter
    return redirect(f'/reconstruct?video_filename={video_filename}')

@app.route('/reconstruct', methods=['GET', 'POST'])
def reconstruct_video():
    """Reconstruct the video from key shares and decrypt."""
    if request.method == 'POST':
        # Reconstruct the encryption key from shares
        key_shares = []
        for i in range(1, 6):
            share_filename = f"key_share_{i}.txt"
            share_filepath = os.path.join(app.config['SHARES_FOLDER'], share_filename)
            if not os.path.exists(share_filepath):
                break
            with open(share_filepath, 'r') as f:
                key_shares.append(f.read())
        
        if len(key_shares) < 3:
            return "Error: Not enough shares to reconstruct the key", 400

        reconstructed_key_hex = SecretSharer.recover_secret(key_shares)
        reconstructed_key = bytes.fromhex(reconstructed_key_hex)
        cipher_suite_reconstructed = Fernet(reconstructed_key)

        # Decrypt the video frames
        video_filename = request.form['video_filename']  # Get the original video filename
        decrypted_frames, frame_shape = decrypt_frames(video_filename, cipher_suite_reconstructed)
        
        # Save reconstructed video
        decrypted_video_path = os.path.join(app.config['DECRYPTED_FOLDER'], f"decrypted_{video_filename}")
        save_video(decrypted_frames, decrypted_video_path, frame_shape)

        # Extract watermark from the first decrypted frame
        extracted_watermark_path = os.path.join(app.config['DECRYPTED_FOLDER'], "extracted_watermark.png")
        cv2.imwrite(extracted_watermark_path, decrypted_frames[0])  # Save the first frame as the extracted watermark

        return redirect(f'/download/{os.path.basename(decrypted_video_path)}')

    # Handle GET request: Get video filename from query parameters
    video_filename = request.args.get('video_filename')
    return render_template('reconstruct.html', video_filename=video_filename)

@app.route('/download/<filename>')
def download_file(filename):
    decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], filename)
    if os.path.exists(decrypted_path):
        return send_file(decrypted_path, as_attachment=True)
    else:
        return "Error: File not found", 404

@app.route('/split_frames/<video_filename>')
def split_frames(video_filename):
    """Display split frames for the given video filename."""
    base_filename = os.path.splitext(video_filename)[0]
    frame_files = []
    i = 1
    while True:
        frame_filename = f"{base_filename}_frame_{i}.bin"
        frame_filepath = os.path.join(app.config['UPLOAD_FOLDER'], frame_filename)
        if not os.path.exists(frame_filepath):
            break
        frame_files.append(frame_filepath)
        i += 1
    
    return render_template('split_frames.html', frame_files=frame_files)

def process_video(video_path, watermark_path):
    """Embed watermark, encrypt, and save encrypted video."""
    # Read video and watermark
    vidcap = cv2.VideoCapture(video_path)
    watermark = cv2.imread(watermark_path)
    
    # Resize watermark to fit the video frame
    ret, first_frame = vidcap.read()
    h, w, _ = first_frame.shape
    watermark_resized = cv2.resize(watermark, (w, h))

    frames = []
    while ret:
        # Embed watermark into the frame
        watermarked_frame = cv2.addWeighted(first_frame, 1, watermark_resized, 0.3, 0)
        encrypted_frame = cipher_suite.encrypt(watermarked_frame.tobytes())
        frames.append(encrypted_frame)
        ret, first_frame = vidcap.read()

    # Save the frame shape
    frame_shape = (h, w)
    with open(os.path.join(app.config['SHARES_FOLDER'], 'frame_shape.pkl'), 'wb') as f:
        pickle.dump(frame_shape, f)

    # Split the encryption key into shares using Shamir's Secret Sharing
    key_hex = key.hex()
    key_shares = SecretSharer.split_secret(key_hex, 3, 5)

    # Save key shares
    save_key_shares(key_shares)

    # Save encrypted video frames
    save_encrypted_frames(frames, os.path.basename(video_path))

def save_key_shares(key_shares):
    """Save key shares in the SHARES_FOLDER."""
    for i, share in enumerate(key_shares):
        share_filename = f"key_share_{i+1}.txt"
        with open(os.path.join(app.config['SHARES_FOLDER'], share_filename), 'w') as f:
            f.write(share)

def save_encrypted_frames(frames, video_filename):
    """Save encrypted frames in the UPLOAD_FOLDER."""
    base_filename = os.path.splitext(video_filename)[0]
    for i, encrypted_frame in enumerate(frames):
        frame_filename = f"{base_filename}_frame_{i+1}.bin"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], frame_filename), 'wb') as f:
            f.write(encrypted_frame)

def decrypt_frames(video_filename, cipher_suite):
    """Decrypt video frames."""
    frames = []
    base_filename = os.path.splitext(video_filename)[0]
    i = 1
    while True:
        frame_filename = f"{base_filename}_frame_{i}.bin"
        frame_filepath = os.path.join(app.config['UPLOAD_FOLDER'], frame_filename)
        if not os.path.exists(frame_filepath):
            break
        with open(frame_filepath, 'rb') as f:
            encrypted_frame = f.read()
        decrypted_frame = cipher_suite.decrypt(encrypted_frame)

        # Load frame shape from the saved file
        with open(os.path.join(app.config['SHARES_FOLDER'], 'frame_shape.pkl'), 'rb') as f:
            frame_shape = pickle.load(f)

        np_frame = np.frombuffer(decrypted_frame, dtype=np.uint8).reshape(frame_shape[0], frame_shape[1], 3)
        frames.append(np_frame)
        i += 1

    return frames, frame_shape

def save_video(frames, video_path, frame_shape):
    """Save frames as a video."""
    height, width = frame_shape
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(video_path, fourcc, 30.0, (width, height))
    
    for frame in frames:
        out.write(frame)
    out.release()

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/performance')
def performance():
    return render_template('performance.html')


if __name__ == '__main__':
    app.run(debug=True)
