print("🧪 Ejecutando app.py correctamente")

from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from config import Config
from functools import wraps

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

print("📦 Configuración cargada:")
print("Host:", Config.MYSQL_HOST)
print("Usuario:", Config.MYSQL_USER)
print("Base de datos:", Config.MYSQL_DATABASE)

# Conexión a la base de datos
try:
    conexion = mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DATABASE
    )
    cursor = conexion.cursor(dictionary=True)
    print("✅ Conectado a la base de datos BIOMA")
except mysql.connector.Error as err:
    print("❌ Error de conexión:", err)
    exit()

# Función para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            flash('Debes iniciar sesión para acceder.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Ruta principal
@app.route('/')
@login_required
def home():
    return render_template('index.html', usuario=session['usuario'])

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['username']
        contraseña = request.form['password']
        cursor.execute("SELECT * FROM Usuario WHERE nombre=%s AND contraseña=%s", (usuario, contraseña))
        user = cursor.fetchone()
        if user:
            session['usuario'] = usuario
            return redirect(url_for('home'))
        flash('Usuario o contraseña incorrectos', 'error')
        return redirect(url_for('login'))
    return render_template('loginyregister.html')

# Registro
@app.route('/register', methods=['POST'])
def register():
    usuario = request.form['username']
    contraseña = request.form['password']
    correo = request.form.get('correo')

    cursor.execute("SELECT * FROM Usuario WHERE nombre=%s", (usuario,))
    if cursor.fetchone():
        flash("El usuario ya existe.", "error")
        return redirect(url_for('login'))

    cursor.execute("INSERT INTO Usuario (nombre, contraseña, correo) VALUES (%s, %s, %s)",
                   (usuario, contraseña, correo))
    conexion.commit()
    flash("Usuario registrado con éxito. Ahora puedes iniciar sesión.", "success")
    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for('login'))

# Rutas protegidas
@app.route('/ecotips')
@login_required
def ecotips():
    return render_template('ecotips.html')

@app.route('/plastico')
@login_required
def plastico():
    return render_template('plastico.html')

@app.route('/papel')
@login_required
def papel():
    return render_template('papel.html')

@app.route('/puntos')
@login_required
def puntos():
    return render_template('puntos.html')

@app.route('/recompensas')
@login_required
def recompensas():
    return render_template('recompensas.html')

@app.route('/carton')
@login_required
def carton():
    return render_template('carton.html')


# Iniciar servidor
if __name__ == '__main__':
    print("🚀 Iniciando Flask...")
    app.run(debug=True)
