import aesgestion as aes
import rsagestion as rsa
import hashgestion as hashg

#Partie SHA256
fichTxt = 'files/sha256/fichTxt.txt'
fichBin = 'files/sha256/fichBin'

monHash = hashg.HashGestion()
print("Calcule du hash SHA256 du fichier texte :")
print(monHash.calculate_file_sha256(fichTxt))
print("\nCalcule du hash SHA256 du fichier binaire :")
print(monHash.calculate_file_sha256(fichBin),"\n")
