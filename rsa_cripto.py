#!/usr/bin/env python3
"""
Programa interactivo de consola para Cifrado y Descifrado Asimétrico (RSA).
Utiliza la librería oficial 'cryptography'.

Funciones principales:
1. generar_claves: Genera un par de claves RSA (privada y pública) y las guarda en formato .pem.
2. cifrar_mensaje: Cifra un mensaje de texto plano con la clave pública usando el esquema OAEP.
3. descifrar_mensaje: Descifra un mensaje cifrado (en formato Base64) usando la clave privada.
4. menu_principal: Interfaz de usuario interactiva en consola con manejo de excepciones.
"""

import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generar_claves(nombre_clave_privada="private_key.pem", nombre_clave_publica="public_key.pem", tamano_clave=2048):
    """
    Genera un nuevo par de claves RSA (Privada y Pública) y las guarda en archivos con formato PEM.
    
    :param nombre_clave_privada: Ruta/nombre del archivo para la clave privada.
    :param nombre_clave_publica: Ruta/nombre del archivo para la clave pública.
    :param tamano_clave: Tamaño de la clave RSA en bits (por defecto 2048 bits).
    """
    try:
        print(f"\n[+] Generando par de claves RSA ({tamano_clave} bits)... Por favor espere.")
        
        # 1. Generar clave privada RSA
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=tamano_clave
        )
        
        # 2. Obtener la clave pública a partir de la privada
        clave_publica = clave_privada.public_key()

        # 3. Serializar la clave privada a formato PEM (sin contraseña para este ejemplo)
        pem_privada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 4. Serializar la clave pública a formato PEM
        pem_publica = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 5. Guardar la clave privada en archivo
        with open(nombre_clave_privada, "wb") as f_priv:
            f_priv.write(pem_privada)

        # 6. Guardar la clave pública en archivo
        with open(nombre_clave_publica, "wb") as f_pub:
            f_pub.write(pem_publica)

        print(f"  Éxito: Clave privada guardada en '{nombre_clave_privada}'")
        print(f"  Éxito: Clave pública guardada en '{nombre_clave_publica}'")

    except Exception as e:
        print(f" Error al generar o guardar las claves: {e}")


def cifrar_mensaje(mensaje, ruta_clave_publica="public_key.pem"):
    """
    Cifra un mensaje de texto con una clave pública RSA usando relleno OAEP con SHA-256.
    Retorna el resultado cifrado codificado en Base64.
    
    :param mensaje: Texto plano que se desea cifrar.
    :param ruta_clave_publica: Archivo PEM que contiene la clave pública.
    :return: Cadena de texto cifrada en Base64 o None si ocurre un error.
    """
    try:
        # Verificar existencia del archivo
        if not os.path.exists(ruta_clave_publica):
            print(f" Error: El archivo de clave pública '{ruta_clave_publica}' no existe.")
            return None

        # Cargar la clave pública desde el archivo PEM
        with open(ruta_clave_publica, "rb") as f_pub:
            datos_pem = f_pub.read()
            clave_publica = serialization.load_pem_public_key(datos_pem)

        # Convertir mensaje a bytes
        mensaje_bytes = mensaje.encode('utf-8')

        # Cifrar el mensaje utilizando RSA con relleno OAEP
        bytes_cifrados = clave_publica.encrypt(
            mensaje_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convertir los bytes cifrados a una cadena de texto en Base64 para fácil manejo
        cifrado_b64 = base64.b64encode(bytes_cifrados).decode('utf-8')
        return cifrado_b64

    except ValueError:
        print(f" Error: El formato de la clave pública en '{ruta_clave_publica}' no es válido.")
        return None
    except Exception as e:
        print(f" Error inesperado durante el cifrado: {e}")
        return None


def descifrar_mensaje(cifrado_b64, ruta_clave_privada="private_key.pem"):
    """
    Descifra un mensaje cifrado en formato Base64 usando la clave privada RSA.
    
    :param cifrado_b64: Mensaje cifrado codificado en Base64.
    :param ruta_clave_privada: Archivo PEM que contiene la clave privada.
    :return: Texto plano descifrado o None si ocurre un error.
    """
    try:
        # Verificar existencia del archivo
        if not os.path.exists(ruta_clave_privada):
            print(f" Error: El archivo de clave privada '{ruta_clave_privada}' no existe.")
            return None

        # Cargar la clave privada desde el archivo PEM
        with open(ruta_clave_privada, "rb") as f_priv:
            datos_pem = f_priv.read()
            clave_privada = serialization.load_pem_private_key(
                datos_pem,
                password=None
            )

        # Decodificar el texto Base64 a bytes cifrados
        try:
            bytes_cifrados = base64.b64decode(cifrado_b64)
        except Exception:
            print(" Error: El formato del mensaje cifrado ingresado no es un Base64 válido.")
            return None

        # Descifrar el mensaje utilizando RSA con relleno OAEP
        bytes_descifrados = clave_privada.decrypt(
            bytes_cifrados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Reconstruir la cadena de texto original
        texto_original = bytes_descifrados.decode('utf-8')
        return texto_original

    except ValueError as ve:
        print(f" Error de descifrado: Es posible que la clave privada no corresponda a la pública usada para cifrar, o que el mensaje esté alterado/dañado. ({ve})")
        return None
    except Exception as e:
        print(f" Error inesperado durante el descifrado: {e}")
        return None


def menu_principal():
    """
    Despliega el menú interactivo en consola para administrar el cifrado/descifrado RSA.
    """
    while True:
        print("\n" + "=" * 50)
        print("    MENÚ DE CRIPTOGRAFÍA ASIMÉTRICA (RSA)")
        print("=" * 50)
        print("  [1] Generar par de claves (Pública y Privada)")
        print("  [2] Cifrar mensaje de texto (Clave Pública)")
        print("  [3] Descifrar mensaje (Clave Privada)")
        print("  [4] Salir")
        print("=" * 50)
        
        opcion = input("Seleccione una opción (1-4): ").strip()

        if opcion == "1":
            file_priv = input("Nombre del archivo para clave privada [private_key.pem]: ").strip() or "private_key.pem"
            file_pub = input("Nombre del archivo para clave pública [public_key.pem]: ").strip() or "public_key.pem"
            generar_claves(nombre_clave_privada=file_priv, nombre_clave_publica=file_pub)

        elif opcion == "2":
            mensaje = input("\nIngrese el mensaje que desea cifrar: ")
            if not mensaje:
                print(" El mensaje no puede estar vacío.")
                continue
            file_pub = input("Ruta de la clave pública [public_key.pem]: ").strip() or "public_key.pem"
            resultado = cifrar_mensaje(mensaje, ruta_clave_publica=file_pub)
            if resultado:
                print("\n MENSAJE CIFRADO EXITOSAMENTE (Formato Base64):")
                print("-" * 50)
                print(resultado)
                print("-" * 50)

        elif opcion == "3":
            cifrado_b64 = input("\nIngrese el mensaje cifrado (en formato Base64): ").strip()
            if not cifrado_b64:
                print(" El mensaje cifrado no puede estar vacío.")
                continue
            file_priv = input("Ruta de la clave privada [private_key.pem]: ").strip() or "private_key.pem"
            resultado = descifrar_mensaje(cifrado_b64, ruta_clave_privada=file_priv)
            if resultado:
                print("\n MENSAJE DESCIFRADO EXITOSAMENTE:")
                print("-" * 50)
                print(resultado)
                print("-" * 50)

        elif opcion == "4":
            print("\n¡Gracias por utilizar el programa de criptografía RSA! Hasta luego.")
            break
        else:
            print("\n Opción no válida. Por favor, intente de nuevo seleccionando un número entre 1 y 4.")


if __name__ == "__main__":
    menu_principal()
