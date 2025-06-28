import socket
import time

# Definir una clave de cifrado
CLAVE = bytearray([0x12])
NUM_BYTES = 3  # Número de bytes a enviar en cada paquete

def data_extractor(datos_enviar, paquete, secuencia):
    """Extrae los datos a enviar y los coloca en el paquete."""
    inicio = secuencia * NUM_BYTES
    finpaquete = 0
    for i in range(NUM_BYTES):
        if inicio + i < len(datos_enviar):
            paquete[i+1] = datos_enviar[inicio+i]
        else:
            paquete[i+1] = 0
            finpaquete = 1  # Indica que se ha alcanzado el final del mensaje
    return finpaquete

def cifrar(paquete: bytearray, clave: bytearray):
    """Cifra los 3 bytes de datos del paquete con la clave proporcionada."""
    for i in range(NUM_BYTES):
        paquete[i+1] ^= clave[0]

def enviar_paquete(cliente, paquete):
    """Envía el paquete al servidor y espera confirmación."""
    confirmacion = False
    printByteArray(paquete)
    while not confirmacion:
        cliente.send(paquete)
        try:
            respuesta = cliente.recv(1024)
            respuesta = bytes(respuesta) # Eliminar espacios en blanco
            if ver_ack(respuesta):
                confirmacion = True
            print("Recibido:", respuesta)
        except socket.timeout:
            print("No se recibió ACK, enviando mensaje nuevamente.")

def ver_ack(respuesta):
    """Verifica si la respuesta es un ACK."""
    if respuesta == b'ACK':
        print("ACK recibido.")
        return True
    else:
        print("ACK no recibido.")
        return False

def printByteArray(byte_array):
    """Imprime el contenido de un bytearray en formato decimal."""
    print("Contenido del bytearray:")
    for byte in byte_array:
        print(f"{byte:03d}", end=' ')
    print()  # Nueva línea al final

def packager(secuencia, paquete, longitud, finpaquete):
    """Empaqueta los datos en un formato específico."""
    paquete[0] = secuencia  # Número de secuencia
    paquete[NUM_BYTES+1] = longitud  # Longitud del mensaje
    paquete[NUM_BYTES+2] = finpaquete  # Indicador de fin de paquete

def calcular_crc16_ibm(paquete: bytearray) -> None:
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

if __name__ == "__main__":
    # formato bytearray [seccuencia, datos x 3, longitud, finpaquete, crc1x2]
    datos_enviar = bytearray("iashfdioahs", 'utf-8')
    paquete = bytearray(5 + NUM_BYTES)  # cabecera (5) + datos (NUM_BYTES)
    sec = 0
    lon = len(datos_enviar)
    finpaquete = 0

    # # Crear socket TCP
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    while True:
        try:
            cliente.connect(("127.0.0.1", 12345))
            print("Conexión exitosa al servidor.")
            cliente.settimeout(5) 
            break
        except ConnectionRefusedError:
            print("Receptor no disponible. Reintentando en 2 segundos...")
            time.sleep(2)
    for i in range(0, len(datos_enviar), 3):
        finpaquete = data_extractor(datos_enviar, paquete, sec)
        printByteArray(paquete)
        cifrar(paquete, CLAVE)
        printByteArray(paquete)
        packager(sec, paquete, lon, finpaquete)
        calcular_crc16_ibm(paquete)
        printByteArray(paquete)

        enviar_paquete(cliente, paquete)
        sec += 1
        print("\n\n")


    cliente.close()