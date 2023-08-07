#!/usr/bin/python3

# Usage: python3 frequence.py fichier_texte

import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
Occurences = {}

def frequence(nomF):
	f = open(nomF , "r")
	text = f.read()
	length = len(text)

	for c in alphabet:
		if length == 0 :
			print(c , 0.0)
		else:
			Occurences[c] = text.count(c)
			print(c , Occurences[c] / length)



frequence(sys.argv[1])



