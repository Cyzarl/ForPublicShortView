import os
import hashlib
import requests
import json
import shutil
import time


#Crea el hash de los archivos
def CalcularHash(archivo, algoritmo = 'sha256'):
    HashAlgoritmo = hashlib.new(algoritmo)
    with open(archivo, 'rb') as file:
        chunk = file.read(8192)
        while chunk:
            HashAlgoritmo.update(chunk)
            chunk = file.read(8192)
    return HashAlgoritmo.hexdigest()


#carga el dato como Hash
def LoadHashData(FileRoute):
    try:
        with open(FileRoute, 'r') as file:
            hashes = {line.strip() for line in file if line.strip()}
            return hashes
    except(FileNotFoundError, IOError) as error:
        print(f"Error al leer el archivo de base de datos {error}")
        print(" ")
        return set()

#Agrega el dato como Hash
def AddHashToData(FileRoute, HashCode):
    with open(FileRoute, 'a') as file:
        file.write(HashCode + '\n')


#usa el API
def CheckVirusAPI(HashCodeT, API_Key):
    
    url = f"https://www.virustotal.com/api/v3/files/{HashCodeT}"
    Headers = {"x-apikey": API_Key}

    try:
        Respond = requests.get(url, headers=Headers)
        if Respond.status_code == 200:
            JsonResponse = Respond.json()
            #si algunos de los atributos inferiores es mayor a 0 entonces si es malicioso
            #esto ya que el api indica que otros antivirus lo han detectado asi.
            if JsonResponse['data']['attribute']['last_analysys_stats']['malicious'] > 0:
                return True

    except Exception as ex:
        print(f"Excepcion/Exclusion al realizar la solicitud a VirusTotal: {ex}")
        print(f"{ex} Es un archivo que puede no ser malicioso o que hubo algun error en la consulta...")
        print(" ")
        return False

#Archivos ya detectados
def FileDetected(archivo, BadArchiveStorage):
    try:
        with open(BadArchiveStorage, 'r') as File:
            Archives = {line.strip() for line in File}
            return archivo in Archives
    except FileNotFoundError:
        return False
    
def DelDeleted(ListaDetectados, Delete):
    try: 
        #abre la lista de detectados
        with open(ListaDetectados, 'r') as File:
            lines = File.readlines()

        DividedLines = [line for line in lines if Delete not in line]

        with open(ListaDetectados, 'w') as File:
            File.writelines(DividedLines)

        print(f"El archivo/documento {ListaDetectados} fue borrado exitosamente")
    
    except FileNotFoundError:
        print(f"El archivo/documento {ListaDetectados} no fue encontrado en la lista")
    
    except Exception as ex:
        print(f"Error, excepcion {ex}")







# para escanear carpetas
def EscaneoCarpetas(carpeta, BaseDatosHash, API_Key):
    threats = []
    for root, dirs, files in os.walk(carpeta):
        for archivo in files:
            RutaCompleta = os.path.join(root, archivo)
            #convierte en harsh los archivos del directorio
            ArchivoHash = CalcularHash(RutaCompleta)
            BadArchiveStorage = 'ListaDetectados.txt'

            if ArchivoHash in BaseDatosHash:
                print(f"El archivo {archivo} es malicioso!")
                threats.append(RutaCompleta)
                print(" ")
                #'a' agrega texto sin borrarlo en el .txt
                if FileDetected(RutaCompleta, BadArchiveStorage):
                    print("No se guardo el Archivo malicioso en la lista, pues ya esta en el.")
                
                else: 
                    with open(BadArchiveStorage, 'a') as DataNameFile:
                        #'\n' Escribe el texto en una nueva linea en la base de datos txt
                        DataNameFile.write(RutaCompleta + '\n')
                
                
            
            #en caso que no este en la base de datos
            else: 
                print(f"Verificando el archivo {archivo} en VirusTotal...")
                if CheckVirusAPI(ArchivoHash, API_Key):
                    print(f"El archivo {archivo} es malicioso.")
                    print(" ")
                    #guarda el hash a la base de datos local
                    threats.append(RutaCompleta)
                    AddHashToData('BaseDatosHash.txt', ArchivoHash)

                    
                    if FileDetected(RutaCompleta, BadArchiveStorage):
                        print(f"No se guardo el Archivo malicioso en la lista, pues {archivo} ya esta en el.")                   
                    
                    else:
                        #'a' agrega texto sin borrarlo en el .txt
                        with open(BadArchiveStorage, 'a') as DataNameFile:
                        #'\n' Escribe el texto en una nueva linea en la base de datos txt
                            DataNameFile.write(archivo + '\n')
                        print(f"El archivo malicioso {archivo} se agrego a la lista de archivos malicioso.")
                    
                else:
                    print(f"El archivo {archivo} no fue detectado como amenaza.")
                    print(" ")


    return threats

if __name__ == '__main__':

    API_Key = 'YourAPI'

    HashDataRoute = 'BaseDatosHash.txt'

    BaseDatosHash = LoadHashData(HashDataRoute)
    

    ArchivoDir = input('Ingrese el directorio que desea escanear: ')
    ArchivoEscanear = fr'{ArchivoDir}'


    TreatsFound = EscaneoCarpetas(ArchivoEscanear, BaseDatosHash, API_Key)

    if TreatsFound:
        print("Archivos Maliciosos encontrados: ")
        for threat in TreatsFound:
            print(threat)
            
            try:
                Delete = input("Le gustaria Borrar los archivos maliciosos encontrados? s/n: ")
                print(" ")
                if Delete.lower() == 's':
                    print("Borrando archivos maliciosos.")
                    print(" ")
                    BadArchiveStorage = 'ListaDetectados.txt'

                    with open(BadArchiveStorage, 'r') as file:
                        NamesRead = {line.strip() for line in file if line.strip()}

                        for EachArchive in NamesRead:

                            if os.path.exists(EachArchive):
                                os.remove(EachArchive)
                                print(f"La carpeta {EachArchive} ha sido eliminada")
                                DelDeleted(BadArchiveStorage , EachArchive)
                                print(" ")

                            elif os.path.isdir(EachArchive):
                                shutil.rmtree(EachArchive)
                                print(f"La carpeta {EachArchive} se borro")
                                DelDeleted(BadArchiveStorage, EachArchive)


                            else:
                                print(f"La carpeta {EachArchive} no existe o ya ha sido eliminado")
                                print(" ")
   

                elif Delete.lower() == 'n':
                    print("Comprendido! Los archivos no se borraran.")
            
            except Exception as Ex:
                print(f"Error {Ex}")

    else:
        print("No se encontraron amenazas.")