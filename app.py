print("Ejecutando app.py correctamente")

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from config import Config
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import mysql.connector
import os
import bcrypt

# -------------------- Configuración Inicial --------------------
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config.from_object(Config)

UPLOAD_FOLDER = 'static/perfiles'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------- Configuración de Mail y Serialización --------------------
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# -------------------- Conexión a la base de datos --------------------
print("Configuración cargada:")
print("Host:", Config.MYSQL_HOST)
print("Usuario:", Config.MYSQL_USER)
print("Base de datos:", Config.MYSQL_DATABASE)

try:
    conexion = mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DATABASE
    )
    cursor = conexion.cursor(dictionary=True)
    print("Conectado a la base de datos BIOMA")
except mysql.connector.Error as err:
    print("Error de conexión:", err)
    exit()

# -------------------- Utilidades --------------------
def generar_hash(contraseña_plana):
    return bcrypt.hashpw(contraseña_plana.encode('utf-8'), bcrypt.gensalt())

def verificar_contraseña(contraseña_plana, contraseña_hash):
    return bcrypt.checkpw(contraseña_plana.encode('utf-8'), contraseña_hash.encode('utf-8'))

# Decoradores para roles y sesiones

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            flash('Debes iniciar sesión.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def solo_admin(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario' not in session or session['rol'] not in ['Administrador', 'superAdministrador']:
            flash('No tienes permiso.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorada

def solo_superadmin(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario' not in session or session['rol'] != 'superAdministrador':
            flash('Solo superadministradores.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorada

# -------------------- Autenticación --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['username']
        contraseña = request.form['password']
        cursor.execute("SELECT * FROM Usuario WHERE nombre=%s", (usuario,))
        user = cursor.fetchone()
        if user and verificar_contraseña(contraseña, user['contraseña']):
            session['usuario'] = usuario
            session['rol'] = user['rol']
            return redirect(url_for('home'))
        flash('Credenciales incorrectas', 'error')
    return render_template('loginyregister.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada correctamente", "success")
    return redirect(url_for('login'))

@app.route('/register', methods=['POST'])
def register():
    usuario = request.form['username']
    contraseña = request.form['password']
    correo = request.form.get('correo')

    cursor.execute("SELECT * FROM Usuario WHERE nombre=%s", (usuario,))
    if cursor.fetchone():
        flash("Ya existe un usuario con ese nombre.", "error")
        return redirect(url_for('login'))

    contraseña_cifrada = generar_hash(contraseña).decode('utf-8')
    cursor.execute("""
        INSERT INTO Usuario (nombre, contraseña, correo, rol)
        VALUES (%s, %s, %s, %s)
    """, (usuario, contraseña_cifrada, correo, 'Reciclador'))
    conexion.commit()
    flash("Usuario registrado con éxito", "success")
    return redirect(url_for('login'))

# -------------------- Recuperación de Contraseña --------------------
@app.route('/recuperar', methods=['GET'])
def recuperar_contraseña():
    return render_template('recuperar.html')

@app.route('/solicitar_token', methods=['POST'])
def solicitar_token():
    correo = request.form['correo']
    cursor.execute("SELECT * FROM Usuario WHERE correo=%s", (correo,))
    user = cursor.fetchone()
    if not user:
        flash("Correo no registrado.", "error")
        return redirect(url_for('login'))

    token = serializer.dumps(correo, salt='recuperar-clave')
    enlace = url_for('reset_password', token=token, _external=True)
    msg = Message("Recuperar contraseña BIOMA", recipients=[correo])
    msg.body = f"Haz clic en el siguiente enlace para cambiar tu contraseña: {enlace}"

    try:
        mail.send(msg)
        flash("Correo enviado. Revisa tu bandeja de entrada.", "success")
    except Exception as e:
        flash(f"Error al enviar correo: {e}", "error")

    return redirect(url_for('login'))

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        correo = serializer.loads(token, salt='recuperar-clave', max_age=600)
    except (SignatureExpired, BadSignature):
        return "El enlace ha expirado o no es válido."

    if request.method == 'POST':
        nueva_contraseña = request.form['password']
        contraseña_cifrada = generar_hash(nueva_contraseña).decode('utf-8')
        cursor.execute("UPDATE Usuario SET contraseña=%s WHERE correo=%s", (contraseña_cifrada, correo))
        conexion.commit()
        flash("Contraseña actualizada.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer.html')

# -------------------- Perfil de Usuario --------------------
@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    cursor.execute("SELECT * FROM Usuario WHERE nombre = %s", (session['usuario'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nueva_contraseña = request.form['contraseña']
        nuevo_correo = request.form['correo']
        foto_actual = user.get('foto') or 'img_avatar.png'

        if 'foto' in request.files:
            archivo = request.files['foto']
            if archivo and archivo.filename != '':
                filename = secure_filename(archivo.filename)
                archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                foto_actual = filename

        nueva_contraseña_cifrada = generar_hash(nueva_contraseña).decode('utf-8')
        cursor.execute("""
            UPDATE Usuario SET nombre=%s, contraseña=%s, correo=%s, foto=%s
            WHERE id_usuario=%s
        """, (nuevo_nombre, nueva_contraseña_cifrada, nuevo_correo, foto_actual, user['id_usuario']))
        conexion.commit()
        session['usuario'] = nuevo_nombre
        flash("Perfil actualizado", "success")
        return redirect(url_for('perfil'))

    return render_template('perfil.html', user=user)

@app.route('/eliminar_cuenta', methods=['POST'])
@login_required
def eliminar_cuenta():
    usuario = session['usuario']
    cursor.execute("SELECT id_usuario, foto FROM Usuario WHERE nombre = %s", (usuario,))
    result = cursor.fetchone()

    if result:
        id_usuario = result['id_usuario']
        foto = result.get('foto')

        if foto and foto != 'img_avatar.png':
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], foto))
            except FileNotFoundError:
                pass

        cursor.execute("DELETE FROM Usuario WHERE id_usuario = %s", (id_usuario,))
        conexion.commit()
        session.clear()
        flash("Tu cuenta ha sido eliminada exitosamente.", "info")
        return redirect(url_for('login'))
    else:
        flash("No se encontró el usuario.", "error")
        return redirect(url_for('perfil'))

# -------------------- Secciones del sitio --------------------
@app.route('/')
@login_required
def home():
    return render_template('index.html', usuario=session['usuario'])

@app.route('/notificar')
@login_required
@solo_admin
def notificar():
    msg = Message('Correo de prueba BIOMA',
                  recipients=['tucorreo@gmail.com'],
                  body='Hola, este es un mensaje de prueba enviado desde BIOMA.')
    try:
        mail.send(msg)
        return "Correo enviado correctamente."
    except Exception as e:
        return f"Error al enviar correo: {e}"

@app.route('/plastico')
@login_required
def plastico():
    return render_template('plastico.html')

@app.route('/papel')
@login_required
def papel():
    return render_template('papel.html')

@app.route('/carton')
@login_required
def carton():
    return render_template('carton.html')

@app.route('/puntos')
@login_required
def puntos():
    return render_template('puntos.html')

@app.route('/ecotips')
@login_required
def ecotips():
    return render_template('ecotips.html')

@app.route('/recompensas')
@login_required
def recompensas():
    return render_template('recompensas.html')

@app.route('/catalogo')
@login_required
def catalogo():
    return render_template('catalogo.html')

# -------------------- Funcionalidad: Solicitar ser administrador --------------------
@app.route('/solicitar_admin', methods=['POST'])
@login_required
def solicitar_admin():
    cursor.execute("UPDATE Usuario SET solicitud_admin = 1 WHERE nombre = %s", (session['usuario'],))
    conexion.commit()
    flash("Has solicitado ser administrador. Espera la aprobación.", "info")
    return redirect(url_for('perfil'))

@app.route('/solicitudes_admin')
@login_required
@solo_admin
def solicitudes_admin():
    cursor.execute("SELECT id_usuario, nombre, correo FROM Usuario WHERE solicitud_admin = 1 AND rol = 'Reciclador'")
    solicitudes = cursor.fetchall()
    return render_template("solicitudes_admin.html", solicitudes=solicitudes)

@app.route('/aprobar_admin', methods=['POST'])
@login_required
@solo_admin
def aprobar_admin():
    usuario_id = request.form['usuario_id']
    cursor.execute("UPDATE Usuario SET rol = 'Administrador', solicitud_admin = 0 WHERE id_usuario = %s", (usuario_id,))
    conexion.commit()
    flash("El usuario fue promovido a Administrador.", "success")
    return redirect(url_for('solicitudes_admin'))

# -------------------- Ejecutar la app --------------------
if __name__ == '__main__':
    print("Iniciando Flask...")
    app.run(debug=True)
