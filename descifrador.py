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
             fcmd()
        # elif res == 2:
        #     #Codigo de RM
        #     rm()
        # elif res == 3:
        #    #Codigo de KUM
        #       kum()
        # elif res == 4:
        #      #Codigo de LCM
        #      lcm()
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
    print("  Descifrador de mensajes polimorfico")
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

#Funcion que obtiene el mensaje
def get_mensaje():
    mesg_hex = input("Ingrese el mensaje cifrado en hexadecimal: ")
    mesg_bytes = bytes.fromhex(mesg_hex)
    psn = int(input("Ingrese el PSN (0-15): "))
    return mesg_bytes, psn 

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

#Secuencias inversas por psn
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

def fcmd():
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
    mesg_bytes, psn, = get_mensaje() #Pedimos y convertimos el mensaje a bytes
    descifrado = descifrar_mensaje(mesg_bytes, psn)
    print(f"{VERDE}Mensaje descifrado: {descifrado.decode('utf-8')}{RESET}") 
    readkey = input("Presione Enter para continuar...")
    return main()


def descifrar_mensaje(cifrado_bytes, psn):
    secuencia = INVERSAS_POR_PSN[psn]
    key_index = psn % len(Keys)
    clave = Keys[key_index]
    
    # Convertir bytes a una lista de enteros de 64 bits
    bloques = []
    for i in range(0, len(cifrado_bytes), 8):
        bloque_bytes = cifrado_bytes[i:i+8]
        bloque = struct.unpack('<Q', bloque_bytes)[0]
        bloques.append(bloque)
    
    # Aplicar las funciones inversas en orden inverso
    bloques_descifrados = []
    for bloque in bloques:
        bloque_descifrado = bloque
        for func in reversed(secuencia):
            bloque_descifrado = func(bloque_descifrado, clave)
        bloques_descifrados.append(bloque_descifrado)
    
    # Convertir de vuelta a bytes
    resultado_bytes = b''
    for bloque in bloques_descifrados:
        resultado_bytes += struct.pack('<Q', bloque)
    
    return resultado_bytes

if __name__ == "__main__":
    main()
