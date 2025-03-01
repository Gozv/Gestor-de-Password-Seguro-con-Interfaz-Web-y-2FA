from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, PasswordEntry
from app.utils import generate_password, CryptoUtils, generate_2fa_secret, get_2fa_uri
import pyotp
import os

crypto = CryptoUtils(os.getenv('ENCRYPTION_KEY').encode())

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('verify_2fa'))
        flash('Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if request.method == 'POST':
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(request.form['code']):
            return redirect(url_for('dashboard'))
        flash('Código 2FA inválido')
    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    decrypted_passwords = []
    for pwd in passwords:
        decrypted_passwords.append({
            'service': pwd.service,
            'password': crypto.decrypt(pwd.encrypted_password)
        })
    return render_template('dashboard.html', passwords=decrypted_passwords)

# ... [Resto de rutas en GitHub] ...