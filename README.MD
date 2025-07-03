
# Protocolo Parada y Espera (Stop-and-Wait) con Sockets en Python

## 📝 Descripción General

Este proyecto implementa una variante del **protocolo Stop-and-Wait**, un esquema fundamental para la transmisión de datos confiable en redes de comunicación. Su objetivo principal es asegurar la **entrega confiable, ordenada y segura de la información**, incluso frente a problemas comunes en el medio de transmisión como la pérdida o corrupción de paquetes.

El protocolo Stop-and-Wait se eligió por su **simplicidad y robustez**, permitiendo que el emisor envíe una única trama y espere una confirmación (ACK o NAK) del receptor antes de proceder con el siguiente paquete. La implementación se realiza utilizando **sockets TCP en Python**, lo que facilita la comunicación bidireccional entre las entidades de emisor y receptor.

## ✨ Características Principales

*   **Control de Flujo Stop-and-Wait**: El emisor envía un paquete y detiene la transmisión hasta recibir una confirmación del receptor. Solo se envía una trama a la vez.
*   **Manejo de Errores Robustos**:
    *   **Números de Secuencia**: Cada paquete de datos incluye un número de secuencia de 1 byte que se incrementa secuencialmente, permitiendo la **identificación única y la detección de paquetes duplicados**. Los paquetes de confirmación también llevan el número de secuencia del paquete al que responden para asegurar la sincronización.
    *   **Checksum CRC-16-IBM**: Utilizado tanto en paquetes de datos como de confirmación para **detectar errores de transmisión**. Si el CRC es incorrecto, el paquete se considera dañado.
    *   **Confirmaciones ACK/NAK**: El receptor envía un ACK (confirmación positiva) si el paquete es correcto y esperado, o un NAK (confirmación negativa) si detecta un error (CRC incorrecto).
    *   **Temporizador (Timeout)**: El emisor inicia un temporizador al enviar cada paquete. Si no recibe una confirmación válida antes de que el temporizador expire, asume una pérdida y **reenvía el paquete**.
*   **Seguridad Básica con Cifrado XOR**: Los 3 bytes de datos útiles dentro de cada paquete son cifrados mediante una **operación XOR con una clave simétrica predefinida** (`0x12`). Este método es ligero y de implementación sencilla, aunque con limitaciones en robustez.
*   **Estructura de Paquetes Definida**:
    *   **Paquete de Datos (7 bytes)**:
        *   `N° de secuencia` (1 byte).
        *   `Datos` (3 bytes, cifrados con XOR).
        *   `Fin de mensaje` (1 byte, indica el último fragmento).
        *   `Checksum` (2 bytes, CRC-16-IBM).
    *   **Paquete de Confirmación (4 bytes)**:
        *   `N° de secuencia confirmado` (1 byte).
        *   `Tipo de confirmación` (1 byte: 1 para ACK, 0 para NAK).
        *   `Checksum` (2 bytes, CRC-16-IBM).
*   **Simulación de Errores**: El código incluye funciones (`envioConError` en emisor y receptor) que simulan **pérdida de paquetes, envío repetido y corrupción de bits** con probabilidades configurables, para probar la robustez del protocolo.

## 🚦 Funcionamiento y Manejo de Errores

El protocolo maneja diversas situaciones para asegurar la entrega correcta de los datos:

*   **Envío Normal**: El emisor envía un paquete, el receptor lo recibe, verifica (CRC y secuencia), descifra los datos y envía un ACK. El emisor recibe el ACK y procede con el siguiente paquete.
*   **Pérdida de Paquete en el Medio**: Si un paquete se pierde, el emisor no recibe la confirmación dentro del tiempo establecido por el temporizador. Esto provoca que el **emisor reenvíe el paquete**.
*   **Errores en el Paquete de Datos (Corrupción)**: Si una trama llega dañada (por ejemplo, un bit cambiado), el receptor detecta el error al verificar el **CRC-16-IBM**. En este caso, el receptor **desecha el paquete y envía un NAK**. El emisor, al recibir el NAK, reenvía la trama.
*   **Errores o Pérdida en la Confirmación (ACK/NAK)**:
    *   Si la confirmación se corrompe (CRC incorrecto) o se pierde, el emisor no recibirá un ACK válido o su temporizador expirará. En ambos casos, el emisor **reenvía el paquete original**.
    *   Si el receptor recibe un **paquete duplicado** (debido a un reenvío por un timeout prematuro o pérdida de ACK), lo identifica mediante el número de secuencia. El receptor **descarta el duplicado y reenvía el ACK** para el paquete que ya había procesado correctamente.

## 🚀 Cómo Ejecutar el Proyecto

Para ejecutar este protocolo, necesitas tener Python instalado en tu sistema.

### ⚙️ Prerrequisitos

*   Python (versión 3.x recomendada)

### 💻 Pasos de Ejecución

1.  **Clonar el Repositorio (o descargar los archivos):**
    ```bash
    git clone <URL_DEL_REPOSITORIO>
    cd <NOMBRE_DEL_REPOSITORIO>
    ```
2.  **Iniciar el Receptor:**
    Abre una terminal y ejecuta el script del receptor:
    ```bash
    python receptor.py
    ```
    El receptor se iniciará y esperará una conexión entrante en el puerto `12345`.
3.  **Iniciar el Emisor:**
    Abre otra terminal (o tab) y ejecuta el script del emisor:
    ```bash
    python emisor.py
    ```
    El emisor intentará conectarse al receptor. Una vez conectado, comenzará a enviar el mensaje dividido en paquetes, mostrando el proceso y los eventos de error simulados.


## 👥 Autores

Este proyecto fue desarrollado por los siguientes integrantes:

*   Martín Alvarado Balboa
*   Isaías Cabrera Gauna
*   Osvaldo Casas-Cordero Navarro
*   Andrés Mardones Domcke

---