from werkzeug.security import generate_password_hash, check_password_hash  # Importar funciones para hashear contraseñas
from flask import jsonify, request  # Importar funciones de Flask para manejar JSON y solicitudes

def validar_contraseña_usuario(indice, mysql):
    data = request.get_json()  # Obtener los datos JSON de la solicitud
    contraseña_ingresada = data.get('contraseña')  # Extraer la contraseña ingresada

    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (indice,))  # Obtener el usuario por ID
    usuario = cursor.fetchone()  # Recuperar un único registro
    cursor.close()  # Cerrar el cursor

    # Verificar si el usuario existe y si la contraseña ingresada coincide con la hasheada
    if usuario and check_password_hash(usuario[3], contraseña_ingresada):
        return jsonify({"message": "Contraseña correcta"}), 200  # Respuesta exitosa
    else:
        return jsonify({"error": "Contraseña incorrecta"}), 401  # Respuesta de error


def verificar_contraseña(indice, mysql):
    data = request.get_json()  # Obtener los datos JSON de la solicitud
    contraseña_ingresada = data.get('contraseña')  # Extraer la contraseña ingresada

    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (indice,))  # Obtener el usuario por ID
    usuario = cursor.fetchone()  # Recuperar un único registro
    cursor.close()  # Cerrar el cursor

    # Verificar si el usuario existe y si la contraseña ingresada coincide con la hasheada
    if usuario and check_password_hash(usuario[3], contraseña_ingresada):
        # Devolver datos del usuario si la contraseña es correcta
        return jsonify({'id': usuario[0], 'usuario': usuario[1], 'correo': usuario[2], 'contraseña': usuario[3]}), 200
    return jsonify({"error": "Contraseña incorrecta"}), 401  # Respuesta de error


def mostrar_datos_usuario(indice, mysql):
    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (indice,))  # Obtener el usuario por ID
    usuario = cursor.fetchone()  # Recuperar un único registro
    cursor.close()  # Cerrar el cursor

    # Verificar si el usuario existe y devolver sus datos
    if usuario:
        return jsonify({'id': usuario[0], 'usuario': usuario[1], 'correo': usuario[2], 'contraseña': usuario[3]}), 200
    return jsonify({"error": "Usuario no encontrado"}), 404  # Respuesta de error


def crear_usuario(mysql):
    try:
        if not request.json:  # Verificar que se reciban datos en formato JSON
            return jsonify({"error": "No se recibieron datos en formato JSON"}), 400

        nuevo_usuario_data = request.json  # Obtener datos del nuevo usuario

        usuario = nuevo_usuario_data.get('usuario')  # Extraer el nombre de usuario
        correo = nuevo_usuario_data.get('correo')  # Extraer el correo
        contraseña = nuevo_usuario_data.get('contraseña')  # Extraer la contraseña

        # Verificar que todos los campos obligatorios estén presentes
        if not usuario or not correo or not contraseña:
            return jsonify({"error": "Faltan campos obligatorios (usuario, correo, contraseña)"}), 400

        cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
        # Verificar si el usuario o el correo ya existen en la base de datos
        cursor.execute("SELECT * FROM usuarios WHERE usuario = %s OR correo = %s", (usuario, correo))
        usuario_existente = cursor.fetchone()

        if usuario_existente:  # Si el usuario o correo ya existen
            cursor.close()
            return jsonify({"error": "El usuario o correo ya existen"}), 409  # Respuesta de error

        contraseña_hasheada = generate_password_hash(contraseña)  # Hashear la contraseña antes de almacenarla

        # Insertar el nuevo usuario en la base de datos
        cursor.execute("INSERT INTO usuarios (usuario, correo, contraseña) VALUES (%s, %s, %s)", 
                       (usuario, correo, contraseña_hasheada))

        nuevo_id = cursor.lastrowid  # Obtener el ID del nuevo usuario insertado
        mysql.connection.commit()  # Confirmar cambios en la base de datos
        cursor.close()  # Cerrar el cursor

        nuevo_usuario_data = {  # Preparar datos del nuevo usuario para la respuesta
            'id': nuevo_id,
            'usuario': usuario,
            'correo': correo
        }
        return jsonify(nuevo_usuario_data), 201  # Respuesta exitosa

    except Exception as e:  # Manejar excepciones
        print(f"Error al crear el usuario: {str(e)}")
        return jsonify({"error": f"Error al crear el usuario: {str(e)}"}), 500  # Respuesta de error


def obtener_usuarios(mysql):
    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    cursor.execute("SELECT * FROM usuarios")  # Obtener todos los usuarios
    usuarios = cursor.fetchall()  # Recuperar todos los registros
    cursor.close()  # Cerrar el cursor

    # Preparar la respuesta con los datos de todos los usuarios
    return jsonify([{'id': usuario[0], 'usuario': usuario[1], 'correo': usuario[2], 'contraseña': usuario[3]} for usuario in usuarios]), 200


def obtener_usuario(indice, mysql):
    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (indice,))  # Obtener el usuario por ID
    usuario = cursor.fetchone()  # Recuperar un único registro
    cursor.close()  # Cerrar el cursor
    # Verificar si el usuario existe y devolver sus datos
    if usuario:
        return jsonify({'id': usuario[0], 'usuario': usuario[1], 'correo': usuario[2], 'contraseña': usuario[3]}), 200
    return jsonify({"error": "Usuario no encontrado"}), 404  # Respuesta de error


def actualizar_usuario(indice, mysql):
    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos
    usuario_actualizado_data = request.get_json()  # Obtener los datos actualizados del usuario

    # Hashear la nueva contraseña antes de actualizar
    contraseña_hasheada = generate_password_hash(usuario_actualizado_data['contraseña'])

    # Actualizar los datos del usuario en la base de datos
    cursor.execute("UPDATE usuarios SET usuario = %s, correo = %s, contraseña = %s WHERE id = %s", 
                   (usuario_actualizado_data['usuario'], usuario_actualizado_data['correo'], contraseña_hasheada, indice))
    mysql.connection.commit()  # Confirmar cambios en la base de datos
    cursor.close()  # Cerrar el cursor
    return jsonify(usuario_actualizado_data), 200  # Respuesta exitosa


def eliminar_usuario(indice, mysql):
    cursor = mysql.connection.cursor()  # Crear un cursor para la base de datos

    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (indice,))  # Verificar si el usuario existe
    usuario = cursor.fetchone()  # Recuperar un único registro

    if not usuario:  # Si el usuario no existe
        cursor.close()
        return jsonify({"error": "Usuario no encontrado"}), 404  # Respuesta de error

    cursor.execute("DELETE FROM usuarios WHERE id = %s", (indice,))  # Eliminar el usuario de la base de datos
    mysql.connection.commit()  # Confirmar cambios en la base de datos
    cursor.close()  # Cerrar el cursor

    return jsonify({"message": "Usuario eliminado correctamente"}), 200  # Respuesta exitosa
