import socket
import time
import random

# Definir una clave de cifrado
CLAVE = bytearray([0x12])
NUM_BYTES = 3  # Número de bytes a enviar en cada paquete

def dataExtractor(datos_enviar, paquete, secuencia):
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

def envioConError(paquete: bytearray, cliente: socket.socket):
    """Simula un error en el envío del paquete."""
    # no enviar, enviar repetidamente, cambiar bit
    # Probabilidades de error:
    prob_no = 0.0  # Probabilidad de no enviar
    prob_repetir = 0.0  # Probabilidad de enviar repetidamente
    prob_cambio = 0.0  # Probabilidad de cambio de bit
    if random.random() < prob_no:
        print("\033[91m[Paquete Perdido].\033[0m")
        return 
    elif random.random() < prob_repetir:
        print("Enviando el paquete dos vezes.")
        cliente.send(paquete)
        time.sleep(0.001)
        cliente.send(paquete)
        return 
    elif random.random() < prob_cambio:
        print("\033[91m[Paquete Corrupto (bit cambiado)]\033[0m")
        # Cambiar un bit aleatorio en el paquete
        index = random.randint(0, len(paquete) - 1)
        paquete[index] ^= 0x01
        cliente.send(paquete)
        return

    print("Enviando el paquete sin errores.")
    # printByteArray(paquete)
    # print("\n\n")
    cliente.send(paquete)
    return

def enviarPaquete(cliente, paquete):
    """Envía el paquete al servidor y espera confirmación."""
    confirmacion = False
    secuencia_inc = False
    while not confirmacion:
        copiaPaquete = bytearray(paquete)  # Hacer una copia del paquete
        if(not secuencia_inc):
            envioConError(copiaPaquete, cliente)
        try:
            respuesta = cliente.recv(1024)
            respuesta = bytes(respuesta) # Eliminar espacios en blanco
            aux = verAck(respuesta, paquete[0])
            if aux == 1:
                confirmacion = True
            if aux == 2:
                secuencia_inc = True
        except socket.timeout:
            print("\033[38;5;220mNo se recibió ACK, enviando mensaje nuevamente.\033[0m")


def verAck(respuesta:bytearray, secuencia:int)-> int:
    """Verifica si la respuesta es un ACK."""
    #fomato de ACK:[secuencia, ACKx1, crc1x2] :4, 00000000 si es ACK, 00000001 si es NUK
    # printByteArray(respuesta)
    print()
 
    print("Confirmación Recibida!")
    if verificarCrc16Ibm(respuesta):
        print("\033[92mCRC-16-IBM verificado correctamente.\033[0m")
        if respuesta[0] == secuencia and respuesta[1] == 1:
            print(f"ACK recibido para el paquete con secuencia {secuencia}: ", end=' ')
            printByteArray(respuesta)
            return 1
        if respuesta[0] == secuencia and respuesta[1] == 0:
            print(f"NAK recibido para el paquete con secuencia {secuencia}: ", end=' ')
            printByteArray(respuesta)
            return 0
        else:
            print("\033[91mConfirmación con secuencia incorrecta: \033[0m", respuesta[0])
            return 2
    else:
        print("\033[91mConfirmación con CRC incorrecto.\033[0m")
    return 0


def printByteArray(byte_array):
    """Imprime el contenido de un bytearray en formato decimal."""
    for byte in byte_array:
        print(f"{byte:03d}", end=' ')
    print()  # Nueva línea al final

def packager(secuencia, paquete, finpaquete):
    """Empaqueta los datos en un formato específico."""
    paquete[0] = secuencia%255  # Número de secuencia
    paquete[NUM_BYTES+1] = finpaquete  # Indicador de fin de paquete

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

if __name__ == "__main__":
    # formato bytearray [seccuencia, datos x 3, longitud, finpaquete, crc1x2]:8
    #fomato de ACK:[secuencia, ACKx1, crc1x2] :4, 00000001 si es ACK, 00000000 si es NUK
    datos_enviar = bytearray("La vida avanza como un rio que no se detiene, fluye por caminos diversos, algunos suaves, otros complejos, pero siempre sigue. A veces parece clara, otras veces es bruma, duda, eco de algo que escapa a la comprension. Cada jornada es una suma de hechos, de pasos dados, de rostros vistos, de palabras dichas o guardadas. Lo curioso es que, incluso en los dias grises, algo dentro de cada ser empuja hacia el alba, hacia la esperanza, hacia la idea de que todo puede ser distinto, de que hay valor en seguir, en mirar al cielo, en cruzar el umbral de lo conocido. Es ese impulso leve pero firme el que marca la diferencia, el que hace que uno respire hondo y diga: sigo aqui, con miedo tal vez, pero firme, vivo, real. Y en ese acto simple se encierra el milagro, la fuerza de la vida misma, que no se mide por lo grande, sino por lo sincero, por lo que habita en lo profundo del alma.", 'utf-8')
    paquete = bytearray(5 + NUM_BYTES)  # cabecera (5) + datos (NUM_BYTES)
    sec = 0
    finpaquete = 0

    # # Crear socket TCP
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    while True:
        try:
            cliente.connect(("127.0.0.1", 12345))
            print("Conexión exitosa al servidor.")
            print()
            cliente.settimeout(1) 
            break
        except ConnectionRefusedError:
            print("Receptor no disponible. Reintentando en 2 segundos...")
            time.sleep(2)

    for i in range(0, len(datos_enviar), NUM_BYTES):
        finpaquete = dataExtractor(datos_enviar, paquete, sec)
        # print("Paquete con datos:")
        # printByteArray(paquete)
        cifrar(paquete, CLAVE)
        packager(sec, paquete, finpaquete)
        calcularCrc16Ibm(paquete)
        print(f"Paquete numero {sec} a enviar:")
        printByteArray(paquete)

        enviarPaquete(cliente, paquete)
        sec += 1
        print("\n\n")


    cliente.close()
