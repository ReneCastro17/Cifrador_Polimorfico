import os #Para limpiar la pantalla
import struct #Para convertir entr bytes y enteros

#Declaramos las variables que se van a ocupar
P = 0 #Primo P
Q = 2 #Primo Q
S = 1234 #Semilla
N = 3 #Numero de Keys
Keys = [] #Matriz de llaves
psn = 0 #Pseudorandom Sequence Nibble
mesg_bytes = b'' #Mensaje en bytes

def main():
    while True:
        print_menu()
        res = opcion()
        if res == 1:
            #Codigo de FCM
             fcm()
        elif res == 2:
            #Codigo de RM
            rm()
        elif res == 3:
           #Codigo de KUM
              kum()
        elif res == 4:
             #Codigo de LCM
             lcm()
        elif res == 0:
            print("Cerrando sesion...")
        break

#Determinamos que la opcion de menu es valida
def opcion():
    op = input("Seleccione una opcion: ")
    if op.isdigit() and int(op) in range(0, 5):
        return int(op) #int() hace que la variable sea un entero
    print("Opción inválida. Intente de nuevo.")

#Este es el menu principal, donde se decide el tipo de mensaje
def print_menu():
    os.system('cls')
    print("=================================")
    print("  Cifrador de mensajes polimorfico")
    print("=================================")
    print("1) FCM:  First Contact Message")
    print("2) RM:   Regular Message")
    print("3) KUM:  Key Update Message")
    print("4) LCM:  Last Contact Message")
    print("0) Salir")

#Acontinuacion vamos a definir las 3 funciones principales para el cifrado de datos
#Mezcladora, Generadora y Mutadora
def mez(P,S):
    P = (P * S)  & 0xFFFFFFFFFFFFFFFF #Esto basicamente limita que el resultado no sea mayor de 64 bits
    return P #P cambio, ahora se considera un nuevo Pn (P0)

def gene(P,S):
    K = (P ^ S) & 0xFFFFFFFFFFFFFFFF #Operacion de prueba
    return K #K es la key generada

def muta(P,S):
    S = (P + S) & 0xFFFFFFFFFFFFFFFF #Operacion de prueba
    return S #S cambio, ahora se considera un nuevo Sn (S0)

#Funcion para generar las keys
def generate_keys(P,Q,S,N):
    global Keys
    Keys = [] #Reiniciamos la matriz de llaves
    i = 0
    while N != 0: #Se crea la matriz de llaves
        P = mez(P,S) 
        Keys.append(gene(P,S))
        S = muta(P,S)
        i += 1 #Contador
        N -= 1 #Decremento
        if N > 0:
            Q = mez(Q,S)
            Keys.append(gene(Q,S))
            S = muta(P,S)
            i += 1
            N -= 1

#Optenemos el mensaje y lo convertimos a bytes
def get_mensaje():  
    mesg = input("Ingrese el mensaje a cifrar: ")
    mesg_bytes = mesg.encode('utf-8')
    mesg_bytes, ceros = rellenar(mesg_bytes)
    psn = get_psn(mesg_bytes)
    #print(f"Mensaje en bytes: {mesg_bytes.hex()}, con {ceros} ceros añadidos y PSN: {psn}")
    return mesg_bytes, psn, ceros

#Rellenamos desde la derecha con ceros hasta que el mensaje sea multiplo de 8 (FUNCIONA)
def rellenar(msg_bytes):
    block_size=8
    cociente, residuo = divmod(len(msg_bytes), block_size) 
    msg_bytes =  (b'\x00' * (block_size - residuo)) + msg_bytes 
    #print(f"Mensaje rellenado: {msg_bytes}")
    return msg_bytes, (block_size - residuo)

#Hay que obtener el psn del ultimo byte
def get_psn(msg_bytes):
    if not msg_bytes:
        return 0
    elif psn > 0:
        byte_psn = msg_bytes[psn]
        return byte_psn & 0x0F
    last_byte = msg_bytes[-1]
    return last_byte & 0x0F

#Fuciones polimorficas reversibles
def f1(x, k):  # XOR
    return x ^ k

def f2(x, k):  # Rotación izquierda
    rotate_bits = k % 64
    return ((x << rotate_bits) | (x >> (64 - rotate_bits))) & 0xFFFFFFFFFFFFFFFF

def f3(x, k):  # Suma modular
    return (x + k) & 0xFFFFFFFFFFFFFFFF

def f4(x, k):  # NOT + XOR
    return ((~x) & 0xFFFFFFFFFFFFFFFF) ^ k

#Elementos claves para el cifrado y descifrado
#Obtenemos el indice de la key a usar
def get_key_index(psn):
    return(psn + Keys.__len__- abs(psn - Keys.__len__())) /2

#Definimos la secuencias de funciones polimorficas
SECUENCIAS_POR_PSN = [
    [f1, f2, f3, f4], [f1, f2, f4, f3], [f1, f3, f2, f4], [f1, f3, f4, f2],
    [f1, f4, f2, f3], [f1, f4, f3, f2], [f2, f1, f3, f4], [f2, f1, f4, f3],
    [f2, f3, f1, f4], [f2, f3, f4, f1], [f2, f4, f1, f3], [f2, f4, f3, f1],
    [f3, f1, f2, f4], [f3, f1, f4, f2], [f3, f2, f1, f4], [f3, f2, f4, f1]
]

#Mensajes de tipo FCM
def fcm():
    os.system('cls')
    VERDE = '\033[92m'
    RESET = '\033[0m'
    print("=================================")
    print("First Contact Message")
    P = int(input("Ingrese un numero primo P: "))
    Q = int(input("Ingrese un numero primo Q: "))
    S = int(input("Ingrese una semilla S: "))
    N = int(input("Ingrese el numero de keys a generar N: "))
    generate_keys(P,Q,S,N)
    #print("Keys generadas: ", Keys)
    mesg_bytes, psn, ceros = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}") 
    print("El psn es: ", psn)
    readkey = input("Presione Enter para continuar...")
    return main()

#Mensajes de tipo RM
def rm():
    os.system('cls')
    VERDE = '\033[92m'
    RESET = '\033[0m'
    print("=================================")
    print("Regular Message")
    if not Keys:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    mesg_bytes, psn, ceros = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}")
    print("El psn es: ", psn)
    readkey = input("Presione Enter para continuar...")
    return main()

#Mensaje de tipo KUM
def kum():
    os.system('cls')
    VERDE = '\033[92m'
    RESET = '\033[0m'
    print("=================================")
    print("Key Update Message")
    if not Keys:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    s = input("Ingrese una nueva semilla S para actualizar las keys: ")
    generate_keys(P,Q,int(s),N)
    mesg_bytes, psn, ceros = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}")
    print("El psn es: ", psn)
    readkey = input("Presione Enter para continuar...")
    return main()

#Mensajde de Tipo LCM
def lcm():
    os.system('cls')
    VERDE = '\033[92m'
    RESET = '\033[0m'
    print("=================================")
    print("Last Key Message")
    if not Keys:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    mesg_bytes, psn, ceros = get_mensaje() 
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}")
    print("El psn es: ", psn)
    del Keys[:]
    print("Keys y parametros eliminados.")
    readkey = input("Presione Enter para continuar...")
    return main()

#Funcion que cifra el mensaje
def cifrar_mensaje(mesg_bytes):
    psn = get_psn(mesg_bytes)
    index = psn % len(Keys)
    clave = Keys[index]
    secuencia = SECUENCIAS_POR_PSN[psn]
    bloques = []
    for i in range(0, len(mesg_bytes), 8):
        bloque_bytes = mesg_bytes[i:i+8]
        # Como ya está rellenado, cada bloque tiene 8 bytes
        bloque = struct.unpack('<Q', bloque_bytes)[0]
        bloques.append(bloque)
    
    # Aplicar las funciones polimórficas
    bloques_cifrados = []
    for bloque in bloques:
        bloque_cifrado = bloque
        for func in secuencia:
            bloque_cifrado = func(bloque_cifrado, clave)
        bloques_cifrados.append(bloque_cifrado)
    
    # Convertir de vuelta a bytes
    resultado_bytes = b''
    for bloque in bloques_cifrados:
        resultado_bytes += struct.pack('<Q', bloque)
    
    return resultado_bytes
    

if __name__ == "__main__":
    main()
