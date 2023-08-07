#!/usr/bin/python3

import sys



decalage = (((ord(sys.argv[2].upper()))- 65) - ((ord(sys.argv[1].upper()))- 65)) % 26

texte = sys.argv[3]

# Usage: python3 cesar.py clef c/d phrase
# Returns the result without additional text
def caesar_cipher(texte, decalage, decrypt=False):
    if decrypt:
        decalage = -decalage
    cipher_text = ""
    for char in texte:
        if char.isalpha():
            decalage_char = chr((ord(char.upper()) + decalage - 65) % 26 + 65)
            if char.islower():
                decalage_char = decalage_char.lower()
            cipher_text += decalage_char
        else:
            cipher_text += char
    return cipher_text

print(caesar_cipher(texte,decalage))

# texte = "HELLO WORLD"
# decalage = 3
# cipher_text = caesar_cipher(texte, decalage)
# print(f"texte clair: {texte}")
# print(f"texte chiffre: {cipher_text}")

# decrypted_text = caesar_cipher(cipher_text, decalage, decrypt=True)
# print(f"texte dechiffre: {decrypted_text}")


