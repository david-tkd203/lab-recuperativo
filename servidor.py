import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def cifrar_rsa(mensaje, clave_publica):
    clave = RSA.import_key(clave_publica)
    cipher_rsa = PKCS1_OAEP.new(clave)
    cifrado_rsa = cipher_rsa.encrypt(mensaje)
    return cifrado_rsa

def descifrar_rsa(cifrado, clave_privada):
    clave = RSA.import_key(clave_privada)
    cipher_rsa = PKCS1_OAEP.new(clave)
    mensaje = cipher_rsa.decrypt(cifrado)
    return mensaje

def cifrar_vigenere(mensaje, clave):
    mensaje_cifrado = ""
    for i in range(len(mensaje)):
        char = mensaje[i]
        if char.isalpha():
            inicio = ord('A') if char.isupper() else ord('a')
            clave_char = clave[i % len(clave)]
            clave_offset = ord(clave_char.upper()) - ord('A')
            mensaje_cifrado += chr((ord(char) - inicio + 26 - clave_offset) % 26 + inicio)
        else:
            mensaje_cifrado += char
    return mensaje_cifrado

def generar_clave_aes():
    return get_random_bytes(32)

def cifrar_aes(mensaje, clave):
    iv = get_random_bytes(16)
    cipher = AES.new(clave, AES.MODE_CFB, iv)
    mensaje_cifrado = iv + cipher.encrypt(mensaje)
    return mensaje_cifrado

def descifrar_aes(mensaje_cifrado, clave):
    iv = mensaje_cifrado[:16]
    cipher = AES.new(clave, AES.MODE_CFB, iv)
    mensaje_descifrado = cipher.decrypt(mensaje_cifrado[16:])
    return mensaje_descifrado

def calcular_md5(archivo):
    hasher = hashlib.md5()
    with open(archivo, 'rb') as f:
        for buf in iter(lambda: f.read(4096), b""):
            hasher.update(buf)
    return hasher.hexdigest()

def main():
    # Configurar el servidor
    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.bind(("localhost", 12345))
    socket_servidor.listen(1)

    print("Esperando conexión del cliente...")
    socket_cliente, direccion_cliente = socket_servidor.accept()
    print(f"Conexión establecida desde {direccion_cliente}")

    # Parte 1: RSA y Vigenere en el servidor
    clave_privada_servidor = RSA.generate(2048).export_key()
    socket_cliente.send(clave_privada_servidor)

    mensaje_cifrado_rsa = socket_cliente.recv(2048)
    mensaje_descifrado_vigenere = descifrar_rsa(mensaje_cifrado_rsa, clave_privada_servidor).decode()

    with open("mensaje_de_salida.txt", "w") as archivo_salida:
        clave_vigenere = "CLAVE"
        mensaje_descifrado = cifrar_vigenere(mensaje_descifrado_vigenere, clave_vigenere)
        archivo_salida.write(mensaje_descifrado)

    print("Mensaje descifrado y guardado en mensaje_de_salida.txt")

    # Parte 2: Sincronizar clave Diffie-Hellman
    clave_privada_servidor_dh = int.from_bytes(get_random_bytes(32), 'big')
    clave_publica_servidor_dh = pow(2, clave_privada_servidor_dh, 999999)
    socket_cliente.send(str(clave_publica_servidor_dh).encode())

    clave_publica_cliente_dh = int(socket_cliente.recv(2048).decode())
    clave_compartida_servidor = pow(clave_publica_cliente_dh, clave_privada_servidor_dh, 999999)
    clave_compartida_servidor = hashlib.sha256(str(clave_compartida_servidor).encode()).digest()

    # Parte 3: AES y reversa en el cliente
    mensaje_cifrado_aes = socket_cliente.recv(2048)
    mensaje_descifrado_aes = descifrar_aes(mensaje_cifrado_aes, clave_compartida_servidor)

    with open("mensaje_de_vuelta.txt", "wb") as archivo_vuelta:
        archivo_vuelta.write(mensaje_descifrado_aes[ : :-1])  # Reversa del texto

    print("Mensaje descifrado con AES y guardado en mensaje_de_vuelta.txt")

    socket_servidor.close()
    socket_cliente.close()

    # Calcular MD5 de archivos
    md5_salida = calcular_md5("mensaje_de_salida.txt")
    md5_vuelta = calcular_md5("mensaje_de_vuelta.txt")

    print(f"MD5 de mensaje_de_salida.txt: {md5_salida}")
    print(f"MD5 de mensaje_de_vuelta.txt: {md5_vuelta}")

if __name__ == "__main__":
    main()
