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
#reprise de la clef aes de quelqu'un d'autre pour dechiffrer un message
print("\nDechiffrement d'un message d'une autre personne avec une cle aes...")
monAes.load_aes_key_from_file('files/aes/import/aes_keys.bin') # Chargement de la clef AES 
monAes.decrypt_file('files/aes/import/test_crypting.txt', 'files/aes/import/decrypt.txt') # Dechiffrage du message
print("Message dechiffre, regarder dans file/aes/import/decrypt.txt")


#Partie RSA
print("\n\n################################## PARTIE RSA ####################################")
fichPublic = 'files/rsa/fichPublic.txt' # Localisation de la clef publique
fichPrive = 'files/rsa/fichPrive.txt' # Localisation de la clef privee
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

#3ème partie
#Chiffrement d'un message dans un fichier texte, ce message doit etre envoyé avec la cle publique pour le dechiffrer
messageAEnvoyer = 'files/rsa/messageChiffre.txt'
monRsa.chargement_clefs(fichPublic, fichPrive) # Chargement de la paire de clefs
message3 = "sudo make me a sandwich - xkcd 2006"
print("Chiffement du message dans un fichier texte : ", message3)
monRsa.chiffre_dans_fichier(message3, messageAEnvoyer) # Chiffrement du message dans un fichier
print("Message chiffre a envoyer sur un autre pc : ", messageAEnvoyer, "\n")
#Reprise de la clef publique et du message chiffre de quelqu'un d'autre
#clefPubImport = 'files/rsa/import/'
#print("\nChargement de la clef publique de quelqu'un d'autre...")
#monRsa.chargement_clef_publique('files/rsa/import/clefPublic.txt')
#print("Fichier deciffre : ", monRsa.dechiffrement_rsa('files/rsa/import/fichTxt.txt'))

#4ème partie
#Chiffrement d'un fichier binaire,meme manipulation que la 3ème partie
binChiffre = 'files/rsa/binChiffre.txt'
message4 = "01001000 01100101 01101100 01101100 01101111"
monRsa.chargement_clefs(fichPublic, fichPrive) # Charegement de la paire de clefs
print("\nChiffrement du message...\n")
monRsa.chiffre_dans_fichier(message4, binChiffre) #chiffrement dans un fichier nomme binChiffre.txt
print("Message chiffre dans : ", binChiffre,"\n")
