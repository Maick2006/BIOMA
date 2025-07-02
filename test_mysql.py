import mysql.connector

try:
    conexion = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="bioma"
    )
    print("✅ Conexión exitosa")
except mysql.connector.Error as err:
    print("❌ Error:", err)