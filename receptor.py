import socket
import time
import random

# Definir una clave de cifrado
CLAVE = bytearray([0x12])
NUM_BYTES = 3  # Número de bytes a enviar en cada paquete

def printByteArray(byte_array):
    """Imprime el contenido de un bytearray en formato decimal."""
    for byte in byte_array:
        print(f"{byte:03d}", end=' ')
    print()  # Nueva línea al final

def envioConError(paquete: bytearray, cliente: socket.socket):
    """Simula un error en el envío del paquete."""
    # no enviar, enviar repetidamente, cambiar bit
    # Probabilidades de error:
    prob_no = 0.0  # Probabilidad de no enviar
    prob_timeout = 0.1 # Probabilidad de enviar repetidamente
    prob_cambio = 0.0  # Probabilidad de cambio de bit
    if random.random() < prob_no:
        printByteArray(paquete)
        print("\033[91m[Paquete Perdido].\033[0m")
        return 
    elif random.random() < prob_timeout:
        printByteArray(paquete)
        print("Timeout Prematuro.")
        time.sleep(1.2)
        cliente.send(paquete)
        return 
    elif random.random() < prob_cambio:
        printByteArray(paquete)
        print("\033[91m[Paquete Corrupto (bit cambiado)]\033[0m")
        # Cambiar un bit aleatorio en el paquete
        index = random.randint(0, len(paquete) - 1)
        paquete[index] ^= 0x01
        cliente.send(paquete)
        return
    
    printByteArray(paquete)
    # print()
    cliente.send(paquete)
    return

def enviarAck(esAck: bool, servidor: socket.socket, secuencia: int):
    #fomato de ACK:[secuencia, ACKx1, crc1x2] :4, 00000001 si es ACK, 00000000 si es NAK
    """Envía un ACK al cliente."""
    # Formato del ACK: [secuencia, ACKx1, crc16x2]

    ack= bytearray([secuencia, int(esAck), 0, 0])  # Secuencia y ACK
    calcularCrc16Ibm(ack)  # Calcula el CRC-16-IBM y lo agrega al final
    if esAck:
        print("Enviando ACK: ", end=' ')
    else:
        print("Enviando NAK: ", end=' ')

    envioConError(ack, servidor)

def descifrar(paquete: bytearray, clave: bytearray = CLAVE):
    """Descifra los bytes del paquete aplicando XOR con la clave."""
    for i in range(len(paquete)):
        paquete[i] ^= clave[0]
        
def calcularCrc16Ibm(paquete: bytearray) -> None:
    """
    Calcula el CRC-16-IBM sobre paquete[:-2] y lo guarda en paquete[-2:].
    El paquete debe tener al menos 2 bytes reservados al final.
    """
    if len(paquete) < 2:
        raise ValueError("El paquete debe tener al menos 2 bytes reservados para el CRC.")

    crc = 0x0000
    for b in paquete[:-2]:  # Excluimos los últimos 2 bytes (donde irá el CRC)
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
        crc &= 0xFFFF

    paquete[-2:] = crc.to_bytes(2, byteorder='little')  # Guardamos el CRC en el mismo paquete


def verificarCrc16Ibm(paquete: bytearray) -> bool:
    """
    Verifica si el CRC-16-IBM de un paquete es correcto.
    Calcula el CRC sobre todos los bytes excepto los últimos 2 (que contienen el CRC esperado),
    y compara si coincide.
    """
    if len(paquete) < 3:
        return False  # No hay suficientes bytes para datos + CRC

    crc = 0x0000  # <- mismo valor inicial que en calcularCrc16Ibm

    for byte in paquete[:-2]:  # Excluye los últimos dos bytes
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
        crc &= 0xFFFF

    # Obtener CRC esperado desde los últimos dos bytes (formato little-endian)
    crc_esperado = paquete[-2] | (paquete[-1] << 8)

    return crc == crc_esperado

def datos_extractor(paquete: bytearray) -> bytearray:
    """Extrae y descifra los datos del paquete recibido."""
    # Extraemos los datos cifrados (posiciones 1 a NUM_BYTES)
    datos_cifrados = paquete[1:NUM_BYTES+1]
    
    # Desciframos los datos (se modifica el array original)
    descifrar(datos_cifrados)
    
    # Convertimos a string (asumiendo UTF-8)
    datos_decodificados = datos_cifrados.decode('utf-8')
    
    # print("Datos descifrados:", ' '.join(f"{b:03d}" for b in datos_cifrados))
    return datos_decodificados

def verificarPaquete(paquete, secuenciaEsperada) -> bool:
    """Verifica si el paquete recibido es correcto."""
    if not verificarCrc16Ibm(paquete):
        print("\033[91mPaquete con CRC incorrecto.\033[0m")
        enviarAck(False, conexion, paquete[0])
        return False
    if int(paquete[0]) != secuenciaEsperada:
        enviarAck(True, conexion, paquete[0])
        print(f"Paquete con secuencia {paquete[0]} duplicado, enviando ACK.")
        return False
    print(f"Paquete con secuencia {paquete[0]} recibido correctamente.")
    return True

def termino(paquete: bytearray) -> bool:
    """Verifica si el paquete indica el fin de la transmisión."""
    return paquete[4] == 1


if __name__ == "__main__":
    # formato bytearray [secuencia, datos x 3, longitud, finpaquete, crc16x2]
    # Crear socket TCP
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('localhost', 12345))
    servidor.listen(1)
    print("Esperando conexión...")
    global conexion
    conexion, direccion = servidor.accept()
    print(f"Conectado desde: {direccion}")
    print()
    
    secuenciaEsperada = 0
    buffer = ""
    
    while True:
        secuenciaEsperada = secuenciaEsperada%255
        paquete = conexion.recv(1024)
        if not paquete:
            print("Conexión cerrada por el cliente.")
            break
            
        paquete = bytearray(paquete)
        print("¡Paquete recibido!:", end=' ')
        printByteArray(paquete)
        
        # Procesamiento del paquete
        if (verificarPaquete(paquete, secuenciaEsperada)):
            print("\033[92mCRC-16-IBM verificado correctamente.\033[0m")
            datos_descifrados = datos_extractor(paquete)
            buffer += datos_descifrados
            secuenciaEsperada += 1
        
            # Enviar confirmación
            enviarAck(True, conexion, paquete[0])
            print("\n\n")
        
            if termino(paquete):
                print("Fin de la transmisión.")
                break

    conexion.close()
    servidor.close()
    print("Datos recibidos completos:", buffer)
