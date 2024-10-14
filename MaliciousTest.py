import hashlib

def MaliciousFileMaker(FileDirectory):
    content = """Este es un archivo malicioso con texto arbitrario detectable."""
    with open(FileDirectory, 'w') as file:
        file.write(content)

def HashCalculator(Archive):
    AlgoHash =hashlib.sha256()
    with open(Archive, 'rb') as file:
        chunk = file.read()
        while chunk:
            AlgoHash.update(chunk)
            chunk = file.read(8192)
            #regresa el valor en hexagesimal, descifrado en hash
    return AlgoHash.hexdigest()


def FileDetected(archivo, BadArchiveStorage):
    try:
        with open(BadArchiveStorage, 'r') as File:
            Archives = {line.strip() for line in File}
            return archivo in Archives
    except FileNotFoundError:
        return False
    

FileDir2 = 'C:\\Users\\rober\\Desktop\\Importantes\\Tareasv2\\Redaccion\\archivo_malicioso.txt'


#crea el archivo malicioso y lo manda al directorio 
MaliciousFileMaker(FileDir2)
#calcula para determinar el hash del archivo
ArchiveHash = HashCalculator(FileDir2)

print(f"Hash del archivo malicioso es: {ArchiveHash}")

HashDataBase = 'BaseDatosHash.txt'


if FileDetected(ArchiveHash, HashDataBase):
    print("No se guardo el Archivo malicioso en la lista, pues ya esta en el.")
    #'a' agrega texto sin borrarlo en el .txt

else: 
    with open(HashDataBase, 'a') as DataBaseFile:
        #'\n' Escribe el texto en una nueva linea en la base de datos txt
        DataBaseFile.write(ArchiveHash + '\n')

    print(f"Hash guardado en {HashDataBase}")


