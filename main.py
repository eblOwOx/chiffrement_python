import aesgestion as aes
import rsagestion as rsa
import hashgestion as hashg

#Partie SHA256
fichTxt = 'files/sha256/fichTxt.txt' # Localisation du fichier texte
fichBin = 'files/sha256/fichBin' # Localisation du fichier binaire

monHash = hashg.HashGestion()
print("Calcule du hash SHA256 du fichier texte :")
print(monHash.calculate_file_sha256(fichTxt)) # Calcul du hash du fichier texte
print("\nCalcule du hash SHA256 du fichier binaire :")
print(monHash.calculate_file_sha256(fichBin),"\n") # Calcul du hash du fichier binaire


#Partie RSA
fichPublic = 'files/rsa/fichPublic' # Localisation de la clef publique
fichPrive = 'files/rsa/fichPrive' # Localisation de la clef privee
fichTxtRsa = 'files/rsa/fichTxtRsa.txt' # Localisation du fichier texte à chiffrer

#1ère partie
monRsa = rsa.RsaGestion()
monRsa.generation_clef(fichPublic, fichPrive, 1024) # Génération d'une paire de clefs
message = "qwerty" # Message a chiffrer
print("Chiffement du message : ", message)
messageChif = monRsa.chiffrement_rsa(message) # Chiffrement du message
print("Message chiffre : ", messageChif, "\n")
print("Dechiffrement du message : ", messageChif)
messageDechif = monRsa.dechiffrement_rsa(messageChif) # Déchiffrement du message
print("Message dechiffre : ", messageDechif, "\n")
