import aesgestion as aes
import rsagestion as rsa
import hashgestion as hashg

#Partie SHA256
print("################################## PARTIE SHA256 #################################")
fichTxt = 'files/sha256/fichTxt.txt' # Localisation du fichier texte
fichBin = 'files/sha256/fichBin' # Localisation du fichier binaire

monHash = hashg.HashGestion()
print("Calcule du hash SHA256 du fichier texte :")
print(monHash.calculate_file_sha256(fichTxt)) # Calcul du hash du fichier texte
print("\nCalcule du hash SHA256 du fichier binaire :")
print(monHash.calculate_file_sha256(fichBin)) # Calcul du hash du fichier binaire


#Partie AES
print("\n\n################################## PARTIE AES ####################################")
keyfile = 'files/aes/aes_key.txt' # Localisation de la clef de session
normal = 'files/aes/normal.txt'
crypt = 'files/aes/cryptaes.txt'
decrypt = 'files/aes/decryptaes.txt'

monAes = aes.AesGestion()
print("generation d'une clef AES")
monAes.generate_aes_key() #Génération de la clé AES
print("Sauvegarde de la clef dans file/aes/")
monAes.save_aes_key_to_file(keyfile) #Sauvegarde de la clé dans un fichier nommé aes_key.txt
monAes.encrypt_file(normal, crypt) #Chiffrement du fichier nommé normal.txt dans un fichier nommé crypt.txt
print("Le contenu du fichier normal.txt dans file/aes/ a ete chiffre en un nouveau fichier nomme cryptaes.txt")
monAes.decrypt_file(crypt, decrypt) #Déchiffrement du fichier crypt.txt dans un fichier nommé 
print("Le fichier cryptaes.txt a ete dechiffre en un nouveau fichier nomme decryptaes.txt")


#Partie RSA
print("\n\n################################## PARTIE RSA ####################################")
fichPublic = 'files/rsa/fichPublic' # Localisation de la clef publique
fichPrive = 'files/rsa/fichPrive' # Localisation de la clef privee
fichTxtChiff = 'files/rsa/fichTxtChiff.txt' # Localisation du fichier texte chiffre

#1ère partie
monRsa = rsa.RsaGestion()
monRsa.generation_clef(fichPublic, fichPrive, 1024) # Génération d'une paire de clefs
message = "qwerty" # Message a chiffrer
print("\nChiffement du message : ", message)
messageChif = monRsa.chiffrement_rsa(message) # Chiffrement du message
print("Message chiffre : ", messageChif, "\n")
print("Dechiffrement du message : ", messageChif)
messageDechif = monRsa.dechiffrement_rsa(messageChif) # Déchiffrement du message
print("Message dechiffre : ", messageDechif, "\n")

#2ème partie
monRsa.chargement_clefs(fichPublic, fichPrive) # Chargement de la paire de clefs
message2 = "Les blagues les plus courtes sont toujours les meilleurs"
print("Chiffement du message dans un fichier texte : ", message2)
monRsa.chiffre_dans_fichier(message2, fichTxtChiff) # Chiffrement du message dans un fichier
print("Message chiffre : ", messageChif, "\n")
print("Dechiffrement du fichier texte...")
message2Dechif = monRsa.dechiffre_fichier(fichTxtChiff) # Déchiffrement du fichier
print("Message dechiffre : ", message2Dechif, "\n")
