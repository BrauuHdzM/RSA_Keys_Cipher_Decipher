from tkinter import *
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import sys

if sys.version_info[0] >= 3 and sys.version_info[1] >= 3:
    time.clock = time.perf_counter

# Función para generar una pareja de llaves RSA
def generar_llaves():
    key = RSA.generate(2048)
    private_key_filename = filedialog.asksaveasfilename(title="Guardar llave privada") + "_private.pem"
    public_key_filename = filedialog.asksaveasfilename(title="Guardar llave pública") + "_public.pem"
    with open(private_key_filename , 'wb') as f:
        f.write(key.export_key('PEM'))
    with open(public_key_filename , 'wb') as f:
        f.write(key.publickey().export_key('PEM'))

# Función para cifrar un archivo de texto plano
def cifrar_archivo():
    # Cargar la llave pública desde un archivo
    public_key_filename = filedialog.askopenfilename(title="Seleccionar llave publica")
    with open(public_key_filename, 'rb') as f:
        llave_publica = RSA.import_key(f.read())

    # Seleccionar el archivo de texto plano a cifrar
    archivo = filedialog.askopenfile(mode='rb', title='Seleccionar archivo')

    # Cifrar el archivo
    cipher = PKCS1_OAEP.new(llave_publica)
    mensaje_cifrado = cipher.encrypt(archivo.read())

    # Guardar el mensaje cifrado en un archivo
    encrypted_file_name = filedialog.asksaveasfilename(defaultextension=".txt", title="Guardar archivo cifrado")
    with open(encrypted_file_name, 'wb') as f:
        f.write(mensaje_cifrado)

# Función para descifrar un archivo cifrado
def descifrar_archivo():
    # Cargar la llave privada desde un archivo
    private_key_filename = filedialog.askopenfilename(title="Seleccionar llave privada")
    with open(private_key_filename, 'rb') as f:
        llave_privada = RSA.import_key(f.read())

    # Seleccionar el archivo cifrado a descifrar
    archivo = filedialog.askopenfile(mode='rb', title='Seleccionar archivo')

    # Descifrar el archivo
    cipher = PKCS1_OAEP.new(llave_privada)
    mensaje_descifrado = cipher.decrypt(archivo.read())

    # Guardar el mensaje descifrado en un archivo
    decrypted_file_name = filedialog.asksaveasfilename(defaultextension=".txt", title="Guardar archivo descifrado")
    with open(decrypted_file_name, 'wb') as f:
        f.write(mensaje_descifrado)

# Función para seleccionar el archivo de la llave pública
def seleccionar_llave_publica():
    archivo = filedialog.askopenfilename(title='Seleccionar archivo')
    llave_publica_archivo.set(archivo)

# Crear la ventana principal
ventana = Tk()
ventana.title('RSA')
ventana.configure(bg="white")

# Crear las variables de control
llave_publica_archivo = StringVar()

# Crear los botones, etiquetas y descripciones
generar_llaves_btn = Button(ventana, text='Generar llaves', command=generar_llaves, font=("Arial", 12), width=20, bg="#007FFF", fg="white")
cifrar_archivo_btn = Button(ventana, text='Cifrar archivo', command=cifrar_archivo, font=("Arial", 12), width=20, bg="#007FFF", fg="white")
descifrar_archivo_btn = Button(ventana, text='Descifrar archivo', command=descifrar_archivo, font=("Arial", 12), width=20, bg="#007FFF", fg="white")

instruccion_generar_llaves = Label(ventana, text="Generar par de llaves pública y privada RSA", font=("Arial", 12), bg="white")
instruccion_cifrar = Label(ventana, text="Cifrar un archivo usando la llave pública", font=("Arial", 12), bg="white")
instruccion_descifrar = Label(ventana, text="Descifrar un archivo usando la llave privada", font=("Arial", 12), bg="white")

# Posicionar los elementos
instruccion_generar_llaves.grid(row=0, column=0, padx=(20, 10), pady=10, sticky=W)
generar_llaves_btn.grid(row=0, column=1, pady=10, padx=(0, 20))

instruccion_cifrar.grid(row=1, column=0, padx=(20, 10), pady=10, sticky=W)
cifrar_archivo_btn.grid(row=1, column=1, pady=10, padx=(0, 20))

instruccion_descifrar.grid(row=2, column=0, padx=(20, 10), pady=10, sticky=W)
descifrar_archivo_btn.grid(row=2, column=1, pady=10, padx=(0, 20))

# Ejecutar la ventana
ventana.mainloop()
