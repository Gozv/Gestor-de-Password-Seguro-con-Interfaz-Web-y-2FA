from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, PasswordEntry
from app.utils import generate_password, CryptoUtils, generate_2fa_secret, get_2fa_uri
import pyotp
import os
import requests

crypto = CryptoUtils(os.getenv('ENCRYPTION_KEY').encode())

# [...] Código previo (home, login, verify_2fa, dashboard)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe')
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        
        # Generar secreto 2FA
        new_user.totp_secret = generate_2fa_secret()
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('setup_2fa'))
    return render_template('register.html')

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    if current_user.totp_secret:
        totp_uri = get_2fa_uri(current_user.username, current_user.totp_secret)
        return render_template('setup_2fa.html', totp_uri=totp_uri)
    return redirect(url_for('home'))

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        service = request.form['service']
        password = request.form['password']
        
        # Cifrar la contraseña
        encrypted_password = crypto.encrypt(password)
        
        new_entry = PasswordEntry(
            user_id=current_user.id,
            service=service,
            encrypted_password=encrypted_password
        )
        
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    generated_password = generate_password()
    return render_template('add_password.html', generated_password=generated_password)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/check_breach', methods=['POST'])
@login_required
def check_breach():
    password = request.form['password']
    hash_prefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]
    response = requests.get(f'https://api.pwnedpasswords.com/range/{hash_prefix}')
    
    if response.status_code == 200:
        hashes = [line.split(':')[0] for line in response.text.splitlines()]
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()[5:]
        return str(full_hash in hashes)
    return 'Error al verificar'