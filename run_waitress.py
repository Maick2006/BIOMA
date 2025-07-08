from waitress import serve
from app import app  # Asegúrate que 'app' sea tu instancia Flask en app.py

if __name__ == '__main__':
    print("🚀 Servidor iniciado con Waitress en http://localhost:8080")
    serve(app, host='0.0.0.0', port=8080)
