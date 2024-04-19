import socket
import threading
import os
import json
import tkinter as tk
from tkinter import messagebox
import base64
from threading import Timer
import ssl

# Variables globales
MI_IP = socket.gethostbyname(socket.gethostname())
PUERTO_DESCUBRIMIENTO = 12345
CARPETA_COMPARTIDA = 'archivos_compartidos'
ARCHIVOS_COMPARTIDOS = set()
NODOS_CONOCIDOS = set()
LISTA_IP_CONECTADAS = set()
TOKEN_SEGURIDAD = "TokenDeEjemplo"
file_timers = {}

# Crear la carpeta compartida si no existe
if not os.path.exists(CARPETA_COMPARTIDA):
    os.makedirs(CARPETA_COMPARTIDA)

def update_file_timer(file_name):
    if file_name in file_timers:
        file_timers[file_name].cancel()  # Cancel the existing timer
    timer = Timer(3.0, lambda: remove_file(file_name))
    timer.start()
    file_timers[file_name] = timer

def remove_file(file_name):
    if file_name in ARCHIVOS_COMPARTIDOS:
        ARCHIVOS_COMPARTIDOS.remove(file_name)
        actualizar_lista_archivos()
    del file_timers[file_name]

def crear_socket_seguro(modo_servidor, server_ip=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH if not modo_servidor else ssl.Purpose.CLIENT_AUTH)
    if modo_servidor:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile='./nodo.crt', keyfile='./nodo.key')
        return ssl_context.wrap_socket(s, server_side=True)
    else:
        if server_ip:
            ssl_context.check_hostname = False
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='./ca.pem')
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        return ssl_context.wrap_socket(s, server_side=False, server_hostname=server_ip)
    
def enviar_mensaje(ip_destino, puerto_destino, mensaje):
    mensaje_json = json.dumps(mensaje).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip_destino, puerto_destino))
            s.sendall(mensaje_json)
        except Exception as e:
            print(f"Error al conectar con el nodo {ip_destino}: {e}")

def recibir_mensajes():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((MI_IP, PUERTO_DESCUBRIMIENTO))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=manejar_conexion, args=(conn, addr)).start()

def manejar_conexion(conn, addr):
    with conn:
        try:
            datos_completos = b''
            while True:
                parte = conn.recv(1024)
                if not parte:
                    break
                datos_completos += parte
            mensaje = json.loads(datos_completos.decode())
            print(f"Mensaje recibido: {mensaje}")
            if mensaje.get('token') != TOKEN_SEGURIDAD:
                print("Token de seguridad inválido.")
                return
            procesar_comando(mensaje, addr[0])
        except json.JSONDecodeError:
            print("Error al decodificar el mensaje JSON.")
        except Exception as e:
            print(f"Error general: {e}")

def procesar_comando(mensaje, ip_origen):
    comando = mensaje.get('comando')
    contenido = mensaje.get('contenido')
    if comando == "ARCHIVOS":
        archivos_recibidos = contenido.split(",")
        for archivo in archivos_recibidos:
            ARCHIVOS_COMPARTIDOS.add(archivo)
            update_file_timer(archivo)
        actualizar_lista_archivos()
    elif comando == "NUEVO_NODO":
        nuevo_nodo_ip = contenido
        NODOS_CONOCIDOS.add(nuevo_nodo_ip)
        LISTA_IP_CONECTADAS.add(nuevo_nodo_ip)
        mensaje_respuesta = {"token": TOKEN_SEGURIDAD, "comando": "ARCHIVOS_SOLICITUD", "contenido": ""}
        enviar_mensaje(nuevo_nodo_ip, PUERTO_DESCUBRIMIENTO, mensaje_respuesta)
    elif comando == "ARCHIVOS_SOLICITUD":
        enviar_lista_archivos(ip_origen)
        actualizar_lista_archivos
    elif comando == "SOLICITUD_DESCARGA":
        enviar_archivo(contenido, ip_origen)
    elif comando == "ENVIO_ARCHIVO":
        nombre_archivo, contenido_archivo = contenido.split(';', 1)
        guardar_archivo_recibido(nombre_archivo, contenido_archivo)

def enviar_archivo(nombre_archivo, ip_destino):
    path_archivo = os.path.join(CARPETA_COMPARTIDA, nombre_archivo)
    try:
        with open(path_archivo, 'rb') as file:
            contenido_archivo = file.read()
    except FileNotFoundError:
        print(f"El archivo {nombre_archivo} no existe en la carpeta compartida.")
        return
    encoded_contenido = base64.b64encode(contenido_archivo).decode('utf-8')
    contenido_mensaje = f"{nombre_archivo};{encoded_contenido}"
    mensaje = {"token": TOKEN_SEGURIDAD, "comando": "ENVIO_ARCHIVO", "contenido": contenido_mensaje}
    enviar_mensaje(ip_destino, PUERTO_DESCUBRIMIENTO, mensaje)

def guardar_archivo_recibido(nombre_archivo, contenido_codificado):
    try:
        contenido_archivo = base64.b64decode(contenido_codificado)
        ruta_archivo = os.path.join(CARPETA_COMPARTIDA, nombre_archivo)
        with open(ruta_archivo, 'wb') as archivo:
            archivo.write(contenido_archivo)
        print(f"Archivo guardado: {ruta_archivo}")
    except Exception as e:
        print(f"Error al guardar el archivo: {e}")

def escanear_carpeta():
    global lista_archivos_locales
    lista_archivos_locales.delete(0, tk.END)
    for archivo in os.listdir(CARPETA_COMPARTIDA):
        lista_archivos_locales.insert(tk.END, archivo)

def actualizar_lista_archivos():
    global lista_archivos_externos
    lista_archivos_externos.delete(0, tk.END)
    archivos_compartidos_externos = ARCHIVOS_COMPARTIDOS - set(os.listdir(CARPETA_COMPARTIDA))
    for archivo in sorted(archivos_compartidos_externos):
        lista_archivos_externos.insert(tk.END, archivo)

def enviar_lista_archivos(ip_destino):
    archivos = ','.join(os.listdir(CARPETA_COMPARTIDA))
    mensaje = {"token": TOKEN_SEGURIDAD, "comando": "ARCHIVOS", "contenido": archivos}
    enviar_mensaje(ip_destino, PUERTO_DESCUBRIMIENTO, mensaje)

def iniciar_gui():
    global lista_archivos_locales, lista_archivos_externos, lista_ip_conectadas, ventana
    ventana = tk.Tk()
    ventana.title("P2P File Sharing")
    btn_escanear = tk.Button(ventana, text="Escanear Carpeta", command=escanear_carpeta)
    btn_escanear.grid(row=0, column=0, padx=5, pady=5)
    lista_archivos_locales = tk.Listbox(ventana, width=50)
    lista_archivos_locales.grid(row=1, column=0, padx=5, pady=5)
    lista_archivos_externos = tk.Listbox(ventana, width=50)
    lista_archivos_externos.grid(row=1, column=1, padx=5, pady=5)
    lista_ip_conectadas = tk.Listbox(ventana, width=20)
    lista_ip_conectadas.grid(row=1, column=2, padx=5, pady=5)
    btn_descargar = tk.Button(ventana, text="Descargar", command=descargar_archivo_seleccionado)
    btn_descargar.grid(row=2, column=1, padx=5, pady=5)
    actualizar_listas_periodicamente()
    ventana.mainloop()

def descargar_archivo_seleccionado():
    archivo_seleccionado = lista_archivos_externos.get(tk.ACTIVE)
    if not archivo_seleccionado:
        messagebox.showerror("Error", "Selecciona un archivo para descargar.")
        return

    for nodo in NODOS_CONOCIDOS:
        mensaje = {"token": TOKEN_SEGURIDAD, "comando": "SOLICITUD_DESCARGA", "contenido": archivo_seleccionado}
        enviar_mensaje(nodo, PUERTO_DESCUBRIMIENTO, mensaje)

def actualizar_listas_periodicamente():
    escanear_carpeta()
    lista_ip_conectadas.delete(0, tk.END)  # Clear the existing list
    for ip in LISTA_IP_CONECTADAS:
        lista_ip_conectadas.insert(tk.END, ip)  # Update with the current list of connected IPs
    for nodo in NODOS_CONOCIDOS:
        solicitar_lista_archivos(nodo)
    ventana.after(5000, actualizar_listas_periodicamente)  # Schedule to run this again

def solicitar_lista_archivos(ip_destino):
    mensaje = {"token": TOKEN_SEGURIDAD, "comando": "ARCHIVOS_SOLICITUD", "contenido": ""}
    enviar_mensaje(ip_destino, PUERTO_DESCUBRIMIENTO, mensaje)

def iniciar_descubrimiento():
    threading.Thread(target=enviar_mensaje_descubrimiento).start()
    threading.Thread(target=recibir_mensajes_descubrimiento).start()
    threading.Thread(target=recibir_mensajes).start()

def enviar_mensaje_descubrimiento():
    mensaje = {"token": TOKEN_SEGURIDAD, "comando": "DESCUBRIMIENTO", "contenido": ""}
    mensaje_json = json.dumps(mensaje).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(mensaje_json, ('<broadcast>', PUERTO_DESCUBRIMIENTO))

def recibir_mensajes_descubrimiento():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', PUERTO_DESCUBRIMIENTO))
        while True:
            data, addr = s.recvfrom(1024)
            mensaje = json.loads(data.decode())
            if mensaje.get('comando') == "DESCUBRIMIENTO" and mensaje.get('token') == TOKEN_SEGURIDAD:
                nuevo_nodo_ip = addr[0]
                NODOS_CONOCIDOS.add(nuevo_nodo_ip)
                LISTA_IP_CONECTADAS.add(nuevo_nodo_ip)
                respuesta = {"token": TOKEN_SEGURIDAD, "comando": "NUEVO_NODO", "contenido": MI_IP}
                enviar_mensaje(nuevo_nodo_ip, PUERTO_DESCUBRIMIENTO, respuesta)

iniciar_descubrimiento()
iniciar_gui()