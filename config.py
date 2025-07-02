class Config:
    # Clave secreta para sesiones Flask
    SECRET_KEY = 'proyecto:Bioma3068389_ProgramaciónSoftware_SENA'

    # Configuración MySQL
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_HOST = '127.0.0.1'
    MYSQL_DATABASE = 'bioma'

    # Configuración para Flask-Mail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'mafecarrillo14@gmail.com'  # Correo desde el cual se envía
    MAIL_PASSWORD = 'yjie lqun dops ykap'        # Clave de aplicación
    MAIL_DEFAULT_SENDER = 'bioma181816@gmail.com'  # Remitente por defecto

    