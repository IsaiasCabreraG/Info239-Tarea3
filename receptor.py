import socket
import time

# Definir una clave de cifrado
CLAVE = bytearray([0x12])
NUM_BYTES = 3  # Número de bytes a enviar en cada paquete

def print_bytearray(byte_array):
    """Imprime el contenido de un bytearray en formato decimal."""
    print("Contenido del bytearray:")
    for byte in byte_array:
        print(f"{byte:03d}", end=' ')
    print()  # Nueva línea al final

def descifrar(paquete: bytearray, clave: bytearray = CLAVE):
    """Descifra los bytes del paquete aplicando XOR con la clave."""
    for i in range(len(paquete)):
        paquete[i] ^= clave[0]

def verificar_crc16_ibm(paquete: bytearray) -> bool:
    """
    Verifica el CRC-16-IBM de un paquete es correcto retornando true si es correcto o false si incorrecto.
    """
    crc = 0xFFFF
    for byte in paquete:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc == 0xF0B8  # Valor esperado del CRC para el paquete recibido

def datos_extractor(paquete: bytearray) -> bytearray:
    """Extrae y descifra los datos del paquete recibido."""
    # Extraemos los datos cifrados (posiciones 1 a NUM_BYTES)
    datos_cifrados = paquete[1:NUM_BYTES+1]
    
    # Desciframos los datos (se modifica el array original)
    descifrar(datos_cifrados)
    
    # Convertimos a string (asumiendo UTF-8)
    try:
        datos_decodificados = datos_cifrados.decode('utf-8')
    except UnicodeDecodeError:
        datos_decodificados = datos_cifrados.decode('latin-1')
    
    print("Datos descifrados:", ' '.join(f"{b:03d}" for b in datos_cifrados))
    return datos_decodificados

def verificarPaquete(paquete, secuencia):
    """Verifica si el paquete recibido es correcto."""
    if not verificar_crc16_ibm(paquete):
        return False
    if secuencia * NUM_BYTES >= len(paquete):
        return False
    return True

def termino(paquete: bytearray) -> bool:
    """Verifica si el paquete indica el fin de la transmisión."""
    return paquete[5] == 1

if __name__ == "__main__":
    # Crear socket TCP
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('localhost', 12345))
    servidor.listen(1)
    print("Esperando conexión...")
    conexion, direccion = servidor.accept()
    print(f"Conectado desde: {direccion}")
    
    sec = 0
    buffer = ""
    
    while True:
        paquete = conexion.recv(1024)
        if not paquete:
            break
            
        paquete = bytearray(paquete)
        print("Paquete recibido:", end=' ')
        print_bytearray(paquete)
        
        # Procesamiento del paquete
        datos_descifrados = datos_extractor(paquete)
        buffer += datos_descifrados
        sec += 1
        
        # Enviar confirmación
        conexion.send(b"ACK")
        
        if termino(paquete):
            print("Fin de la transmisión.")
            break

    conexion.close()
    servidor.close()
    print("Datos recibidos completos:", buffer)