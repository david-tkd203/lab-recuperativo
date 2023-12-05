import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def cifrar_vigenere(mensaje, clave):
    mensaje_cifrado = ""
    for i in range(len(mensaje)):
        char = mensaje[i]
        if char.isalpha():
            inicio = ord('A') if char.isupper() else ord('a')
            clave_char = clave[i % len(clave)]
            clave_offset = ord(clave_char.upper()) - ord('A')
            mensaje_cifrado += chr((ord(char) - inicio + clave_offset) % 26 + inicio)
        else:
            mensaje_cifrado += char
    return mensaje_cifrado

def cifrar_rsa(mensaje, clave_publica):
    clave = RSA.import_key(clave_publica)
    cipher_rsa = PKCS1_OAEP.new(clave)
    cifrado_rsa = cipher_rsa.encrypt(mensaje)
    return cifrado_rsa

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

def main():
    # Configurar el cliente
    socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_cliente.connect(('localhost', 12345))

    # Parte 1: RSA y Vigenere en el cliente
    clave_privada_cliente = socket_cliente.recv(2048).decode()
    
    with open("mensaje_entrada.txt", "r") as file:
        mensaje_entrada = file.read()

    clave_vigenere = "CLAVE"
    mensaje_vigenere = cifrar_vigenere(mensaje_entrada, clave_vigenere)

    mensaje_cifrado_rsa = cifrar_rsa(mensaje_vigenere.encode(), clave_privada_cliente)
    socket_cliente.send(mensaje_cifrado_rsa)

    # Parte 2: Sincronizar clave Diffie-Hellman
    clave_privada_cliente_dh = int.from_bytes(get_random_bytes(32), 'big')
    clave_publica_cliente_dh = pow(2, clave_privada_cliente_dh, 999999)
    socket_cliente.send(str(clave_publica_cliente_dh).encode())

    clave_publica_servidor_dh = int(socket_cliente.recv(2048).decode())
    clave_compartida_cliente = pow(clave_publica_servidor_dh, clave_privada_cliente_dh, 999999)
    clave_compartida_cliente = hashlib.sha256(str(clave_compartida_cliente).encode()).digest()

    # Parte 3: AES y reversa en el cliente
    mensaje_cifrado_aes = cifrar_aes(mensaje_entrada.encode(), clave_compartida_cliente)
    socket_cliente.send(mensaje_cifrado_aes)

    print("Mensaje cifrado con AES y enviado al servidor")

    socket_cliente.close()

if __name__ == "__main__":
    main()
