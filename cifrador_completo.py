import os #Para limpiar la pantalla
import struct #Para convertir entero bytes y enteros

#Declaramos las variables que se van a ocupar
P, PD = 0, 0  # Primo P 
Q, QD = 2, 2  # Primo Q 
S, SD = 1234, 321  # Semilla 
N, ND = 3, 2  # Número de Keys 
Keys, KeysD = [], []  # Matriz de llaves 
psn, psnD = 0, 0  # Pseudorandom Sequence Nibble 
mesg_bytes, mesgd_bytes = b'', b''  # Mensaje en bytes 

def main():
    os.system('cls')
    print("================================================")
    print("  Cifrador y Descifrador de mensajes polimorfico")
    print("================================================")
    menu = input("Seleccione una opcion:\n1) Cifrador\n2) Descifrador\n0) Salir\nIngrese una opcion: ")
    if menu == '1':
        while True:
            os.system('cls')
            print("==================================")
            print("  Cifrador de mensajes polimorfico")
            print("==================================")
            print_menu()
            res = opcion()
            if res == 1:
                fcm()
            elif res == 2:
                rm()
            elif res == 3:
                kum()
            elif res == 4:
                lcm()
            elif res == 0:
                print("Cerrando sesion...")
            break
    elif menu == '2':
        while True:
            os.system('cls')
            print("=====================================")
            print("  Descifrador de mensajes polimorfico")
            print("=====================================")
            print_menu()
            res = opcion()
            if res == 1:
                 fcmd()
            elif res == 2:
                 rmd()
            elif res == 3:
                 kumd()
            elif res == 4:
                 lcmd()
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
    print("1) FCM:  First Contact Message")
    print("2) RM:   Regular Message")
    print("3) KUM:  Key Update Message")
    print("4) LCM:  Last Contact Message")
    print("0) Salir")

#Acontinuacion vamos a definir las 3 funciones principales para el cifrado de datos
#Mezcladora, Generadora y Mutadora
def mez(P,S):
    P = (P * S)  & 0xFFFFFFFFFFFFFFFF #Esto agrega una mascara de 64 bits
    rotate_bits = S % 64 #Rotamos a la izquierda
    P = ((P << rotate_bits) | (P >> (64 - rotate_bits))) & 0xFFFFFFFFFFFFFFFF
    return P #P cambio, ahora se considera un nuevo Pn (P0)

def gene(P,S):
    K = (P ^ S) & 0xFFFFFFFFFFFFFFFF # ^ es un XOR
    K = K ^ (0xDEADBEEF12365412) #Constante
    rotate_bits = P %  64 #Rotamos a la derecha
    K = ((K >> rotate_bits) | (K << (64 - rotate_bits))) & 0xFFFFFFFFFFFFFFFF
    return K #K es la key generada

def muta(P,S):
    S = (P + S) & 0xFFFFFFFFFFFFFFFF 
    S = S ^ (0xC0FFEE1234567890) #Constante
    rotate_bits = P % 64 #Rotamos a la izquierda
    S = ((S << rotate_bits) | (S >> (64 - rotate_bits))) & 0xFFFFFFFFFFFFFFFF
    return S #S cambio, ahora se considera un nuevo Sn (S0)

#Funcion para generar las keys
def generate_keys(P,Q,S,N):
    global Keys
    Keys = [] #Reiniciamos la matriz de llaves
    while N != 0: #Se crea la matriz de llaves
        P = mez(P,S) 
        Keys.append(gene(P,Q))
        S = muta(Q,S)
        N -= 1 #Decremento
        if N > 0:
            Q = mez(Q,S)
            Keys.append(gene(Q,P))
            S = muta(P,S)
            N -= 1

def generate_keysD(PD,QD,SD,ND):
    global KeysD
    KeysD = [] #Reiniciamos la matriz de llaves
    i = 0
    while ND != 0: #Se crea la matriz de llaves
        PD = mez(PD,SD) 
        KeysD.append(gene(PD,QD))
        SD = muta(QD,SD)
        i += 1 #Contador
        ND -= 1 #Decremento
        if ND > 0:
            QD = mez(QD,SD)
            KeysD.append(gene(QD,PD))
            SD = muta(PD,SD)
            i += 1
            ND -= 1

#Optenemos el mensaje y lo convertimos a bytes
def get_mensaje():  
    mesg = input("Ingrese el mensaje a cifrar: ")
    mesg_bytes = mesg.encode('utf-8')
    mesg_bytes, ceros = rellenar(mesg_bytes)
    psn = get_psn(mesg_bytes)
    #print(f"Mensaje en bytes: {mesg_bytes.hex()}, con {ceros} ceros añadidos y PSN: {psn}")
    return mesg_bytes, psn, ceros

def get_mensajed():
    mesg_hex = input("Ingrese el mensaje cifrado en hexadecimal: ")
    mesg_bytesd = bytes.fromhex(mesg_hex)
    psnD = int(input("Ingrese el PSN (0-15): "))
    return mesg_bytesd, psnD

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

#Funciones inversas
def f1_inv(x, k):
    # misma operación para invertir
    return x ^ k

def f2_inv(x, k):  # Rotación derecha, inverso de rotar a la izquierda
    rotate_bits = k % 64
    return ((x >> rotate_bits) | (x << (64 - rotate_bits))) & 0xFFFFFFFFFFFFFFFF

def f3_inv(x, k):
    return (x - k) & 0xFFFFFFFFFFFFFFFF

def f4_inv(x, k):
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

INVERSAS_POR_PSN = [
    [f1_inv, f2_inv, f3_inv, f4_inv], [f1_inv, f2_inv, f4_inv, f3_inv],
    [f1_inv, f3_inv, f2_inv, f4_inv], [f1_inv, f3_inv, f4_inv, f2_inv],
    [f1_inv, f4_inv, f2_inv, f3_inv], [f1_inv, f4_inv, f3_inv, f2_inv],
    [f2_inv, f1_inv, f3_inv, f4_inv], [f2_inv, f1_inv, f4_inv, f3_inv],
    [f2_inv, f3_inv, f1_inv, f4_inv], [f2_inv, f3_inv, f4_inv, f1_inv],
    [f2_inv, f4_inv, f1_inv, f3_inv], [f2_inv, f4_inv, f3_inv, f1_inv],
    [f3_inv, f1_inv, f2_inv, f4_inv], [f3_inv, f1_inv, f4_inv, f2_inv],
    [f3_inv, f2_inv, f1_inv, f4_inv], [f3_inv, f2_inv, f4_inv, f1_inv]
]

#Convertir el mensaje a utf-8
def convertir_mensaje(mensaje):
    VERDE = '\033[92m'
    RESET = '\033[0m'
    try:
        print(f"{VERDE}Mensaje descifrado: {mensaje.decode('utf-8')}{RESET}")
    except UnicodeDecodeError:
        print("El mensaje descifrado no es un texto válido en UTF-8.")

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
    evaluar_calidad_llaves(Keys, "FCM") #Prueba
    #print("Keys generadas: ", Keys)
    mesg_bytes, psn, ceros = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}") 
    print("El psn es: ", psn)
    readkey = input("Presione Enter para continuar...")
    return main()

def fcmd():
    os.system('cls')
    print("=================================")
    print("First Contact Message")
    PD = int(input("Ingrese un numero primo P: "))
    QD = int(input("Ingrese un numero primo Q: "))
    SD = int(input("Ingrese una semilla S: "))
    ND = int(input("Ingrese el numero de keys a generar N: "))
    generate_keysD(PD,QD,SD,ND)
    evaluar_calidad_llaves(KeysD, "FCM")
    #print("Keys generadas: ", Keys)
    mesg_bytesd, psnD, = get_mensajed() #Pedimos y convertimos el mensaje a bytes
    descifrado = descifrar_mensaje(mesg_bytesd, psnD)
    convertir_mensaje(descifrado)
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

def rmd():
    os.system('cls')
    print("=================================")
    print("Regular Message")
    if not KeysD:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    mesg_bytesd, psnD = get_mensajed() #Pedimos y convertimos el mensaje a bytes
    resultado = descifrar_mensaje(mesg_bytesd, psnD)
    convertir_mensaje(resultado)
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
    evaluar_calidad_llaves(Keys, "KUM")
    mesg_bytes, psn, ceros = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    resultado = cifrar_mensaje(mesg_bytes)
    print(f"{VERDE}Mensaje cifrado: {resultado.hex()}{RESET}")
    print("El psn es: ", psn)
    readkey = input("Presione Enter para continuar...")
    return main()

def kumd():
    os.system('cls')
    print("=================================")
    print("Key Update Message")
    if not KeysD:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    SD = int(input("Ingrese una nueva semilla S para actualizar las keys: "))
    generate_keysD(PD,QD,SD,ND)
    evaluar_calidad_llaves(KeysD, "KUM")
    #print("Keys generadas: ", Keys)
    mesg_bytesd, psnD, = get_mensajed() #Pedimos y convertimos el mensaje a bytes
    descifrado = descifrar_mensaje(mesg_bytesd, psnD)
    convertir_mensaje(descifrado)
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

def lcmd():
    os.system('cls')
    print("=================================")
    print("Last Key Message")
    if not KeysD:
        print("No hay keys generadas. Por favor, genere las keys primero usando FCM.")
        readkey = input("Presione Enter para continuar...")
        return main()
    mesg_bytesd, psnD = get_mensajed() 
    resultado = descifrar_mensaje(mesg_bytesd, psnD)
    convertir_mensaje(resultado)
    del KeysD[:]
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
    
#Funcion que descifra el mensaje
def descifrar_mensaje(cifrado_bytes, psnD):
    secuenciaD = INVERSAS_POR_PSN[psnD]
    key_indexD = psnD % len(KeysD)
    claveD = KeysD[key_indexD]
    
    # Convertir bytes a una lista de enteros de 64 bits
    bloquesD = []
    for i in range(0, len(cifrado_bytes), 8):
        bloque_bytesD = cifrado_bytes[i:i+8]
        bloque = struct.unpack('<Q', bloque_bytesD)[0]
        bloquesD.append(bloque)
    
    # Aplicar las funciones inversas en orden inverso
    bloques_descifrados = []
    for bloque in bloquesD:
        bloque_descifrado = bloque
        for func in reversed(secuenciaD):
            bloque_descifrado = func(bloque_descifrado, claveD)
        bloques_descifrados.append(bloque_descifrado)
    
    # Convertir de vuelta a bytes
    resultado_bytesD = b''
    for bloque in bloques_descifrados:
        resultado_bytesD += struct.pack('<Q', bloque)
    
    return resultado_bytesD



def evaluar_calidad_llaves(llaves, nombre):
    if not llaves: #Evaluas existencia de las llaves
        print("No hay llaves para evaluar")
        return
    
    print(f"\n=== Evaluación de llaves ({nombre}) ===")
    
    # Distribución de bits
    total_bits = len(llaves) * 64
    unos = sum(bin(k).count('1') for k in llaves) #Cuenta cuanto unos hay en el entero de las llaves
    proporcion_unos = unos / total_bits #Queres que la mitad sean uno, la otra mitad ceros
    
    print(f"Proporción de unos: {proporcion_unos:.3f} (ideal: 0.5)\n")
    if proporcion_unos < 0.4 or proporcion_unos > 0.6: #Mensaje de advertencia en caso no se cumpla la proporcion
        print("ADVERTENCIA: La proporcion de unos en las llaves no es adecuada. Reconciderar valores\n")
    
    # Entropía aproximada
    from math import log2
    if proporcion_unos == 0 or proporcion_unos == 1: #Si todos son unos o ceros
        entropia = 0
    else:
        entropia = - (proporcion_unos * log2(proporcion_unos) + (1-proporcion_unos) * log2(1-proporcion_unos))#Entropia de Shannon
    print(f"Entropía aproximada: {entropia:.3f} bits/bit (ideal: 1.0)\n")
    if entropia < 0.9:
        print("ADVERTENCIA: La entropía es baja, las llaves no son suficientemente aleatorias\n")
    
    #Diferencias entre llaves consecutivas (efecto avalancha en criptografia)
    if len(llaves) > 1:
        diferencias = []
        for i in range(len(llaves)-1):
            diff = bin(llaves[i] ^ llaves[i+1]).count('1') #Cuenta los bits diferentes entre dos llaves
            diferencias.append(diff)
        diff_promedio = sum(diferencias) / len(diferencias)
        print(f"Diferencia promedio entre llaves: {diff_promedio:.1f} bits (ideal: 32)\n")
        if diff_promedio < 20:
            print("ADVERTENCIA: Las llaves son demasiado similares entre sí\n")

if __name__ == "__main__":
    main()

