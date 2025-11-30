# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "nebula_login_secret_2025_key_change_me_in_production"

# Inicializar base de datos
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL)''')
        conn.commit()

# Hash simple con SHA-256 (para producción usa bcrypt)
def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = hash_password(request.form['password'])

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()

    if user:
        session['user'] = username
        return redirect(url_for('dashboard'))
    else:
        flash('Usuario o contraseña incorrectos', 'error')
        return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = hash_password(request.form['password'])

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('¡Cuenta creada con éxito! Ya puedes iniciar sesión', 'success')
        except sqlite3.IntegrityError:
            flash('Ese nombre de usuario ya existe', 'error')
    
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', username=session['user'])
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
  
