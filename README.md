# Sistema de Intercambio de Archivos P2P (peer-to-peer) mediante Middleware

Esta aplicación en Python permite el intercambio de archivos peer-to-peer (P2P) dentro de una red local. Utiliza sockets para la comunicación en red, permitiendo a los usuarios compartir y descargar archivos de manera dinámica entre los nodos conocidos en la red.

## Características

- Compartir Archivos: Comparte archivos de manera dinámica con todos los pares conectados.
- Descubrimiento de Archivos: Descubre automáticamente los archivos disponibles en la red.
- Descarga de Archivos: Selecciona y descarga archivos de cualquier par dentro de la red.
- Actualizaciones Automáticas de la Lista de Archivos: Actualiza periódicamente las listas de archivos de todos los pares conectados.
- Token de Seguridad: Utiliza un mecanismo de token de seguridad básico para validar la comunicación entre pares.
- SSL: Maneja las conexiones por medio de conexiones seguras SSL.

## Instalación de Dependencias

Para garantizar el correcto funcionamiento del sistema, es necesario instalar las dependencias requeridas. Se proporcionan dos archivos de requisitos:

- `requirements.txt`: Contiene las dependencias necesarias para la correcta ejecución.

Puedes instalar las dependencias ejecutando los siguientes comandos:

```bash
pip install -r requirements.txt  # Instalar paquetes 
```

## Uso

1. **Iniciar la Aplicación**
   Ejecuta el script para iniciar la interfaz gráfica. La aplicación se vinculará automáticamente a la IP de tu máquina y comenzará a escuchar conexiones y mensajes entrantes.

2. **Compartir Archivos**
   Coloca cualquier archivo que desees compartir en la carpeta 'archivos_compartidos' creada por la aplicación.

3. **Descargar Archivos**
   Usa la interfaz gráfica para seleccionar y descargar archivos de la lista de archivos disponibles en la red.
