# Sorbonne Université 3I024 2021-2022
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : Hami Islam 21208634
# Etudiant.e 2 : Bensadok Yanis 28708067

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# Fréquence moyenne des lettres en français
freq_FR = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]


# Retourne la fréquence de toutes les lettres de l'alphabet de la langue française
def frequence(nomF):
    f = open(nomF , "r")
    text = f.read()
    length = len(text)
    if length != 0 : 
        for i in range(len(alphabet)):
            freq_FR[i] = text.count(alphabet[i])/length

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    @param txt : le texte à chiffrer 
    @param key : cle du chifrement 
    @return textChiffre : le résultat du chiffrement
    """
    textChiffre= ""
    for char in txt:
        if char.isalpha():
            decalage_char=chr((ord(char) - 65 + key)% 26 +65) if char.isupper() else chr((ord(char)- 97 + key)% 26 + 97)
            textChiffre += decalage_char
        else:
            textChiffre += char
    return textChiffre

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    @param txt : le texte à déchiffrer 
    @param key : cle du déchifrement 
    @return textDechiffre : le résultat du déchiffrement
    """
    textDechiffre=""
    for char in txt:
        if char.isalpha():
            decalage_char= chr((ord(char) - key -65)%26 + 65)
            if char.islower():
                decalage_char = decalage_char.lower()
            textDechiffre+=decalage_char
        else:
            textDechiffre+=char    
    return textDechiffre

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    @param txt : le texte à chiffrer (il doit etre en majuscule)
    @param key : cle du chifrement 
    @return textChiffre : le résultat du chiffrement
    """
    key_lenght=len(key)
    txt_int=[ord(i) - 65 for i in txt]
    textChiffre=""
    for i, val in enumerate(txt_int):
        decalage = key[i%key_lenght]
        char = (val + decalage) %26
        textChiffre += chr(char +65)
    return textChiffre

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    @param txt : le texte à déchiffrer (il doit etre en majuscule)
    @param key : cle du déchifrement 
    @return textDechiffre : le résultat du déchiffrement
    """
    key_lenght=len(key)
    txt_int=[ord(i) - 65 for i in txt]
    textDechiffre=""
    for i, val in enumerate(txt_int):
        decalage = key[i % key_lenght]
        char = (val - decalage)%26
        textDechiffre += chr(char + 65)
    return textDechiffre

# Analyse de fréquences
def freq(txt):
    """
    @param txt: un texte 
    @return hist : c'est la tableau d'occurence de chaque lettre de l'alphabet apparut dans le texte 
    """
    hist=[0.0]*len(alphabet)
    if len(txt) != 0 : 
        for i in range(len(alphabet)):
            hist[i] = txt.count(alphabet[i])
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    @param txt : un texte
    @return frequence.index(max(frequence)) : l'indice de la lettre ayant la frequence maximale dans le texte
    """
    frequence=freq(txt)
    return frequence.index(max(frequence))

# indice de coïncidence
def indice_coincidence(hist):
    """
    @param hist : tableau qui correspond aux occurences des lettres d'un texte
    @return avg : indice de coincidence
    """
    s = 0
    n=sum(hist)
    for count in hist:
        s += count * (count - 1)
    avg = s / (n* (n - 1))

    return avg


# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    @param cipher : le texte chiffré dans lequel on detecte la longueur de la clé
    @return : la longueur de la clé
    """
    for key_length in range(1, 20 + 1):
        avg = 0
        columns = [''] * key_length
        for i, letter in enumerate(cipher):
            columns[i % key_length] += letter

        for column in columns:
            avg += indice_coincidence(freq(column))
        avg /= key_length

        if avg > 0.06:
            return key_length
    return -1
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    @param cipher : le texte chiffré 
    @param key_length :  la longueur de la clé avec laquelle le texte a était chiffré 
    @return decalages: la clé sous forme de tableau de décalages
    """
    decalages=[0]*key_length

    columns = [''] * key_length
    for i, letter in enumerate(cipher):
        columns[i % key_length] += letter

    for i in range(len(columns)):
        e = lettre_freq_max(columns[i]) # l'indice de la lettre dans l'alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        decalages[i] = (e - 4) % 26

    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    @param cipher : le texte chiffré 
    @return : le texte cryptanalysé
    """

    k = longueur_clef(cipher)
    cle=clef_par_decalages(cipher,k)
    return dechiffre_vigenere(cipher,cle)

    # L'efficacité de notre cryptanalyse dépend de la longueur du texte car on cherche la clef selon l'hypothèse que la freq max de nos colonnes 
    # est un E donc si le texte n'est pas assez long l'hypothèse peut facilement être fausse .

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    @param h1 : tableau de frequence du texte 1
    @param h2 : tableau de frequence du texte 2 à decaler
    @param d : l'indice de decalage
    @return : indice de coicidence mutuelle des deux texte1 et texte2 decalé avec d positions
    """

    """
    Calculates the mutual index of coincidence between two texts.
    """
    n = len(h1)

    n1 = sum(h1)
    n2 = sum(h2)
    icm = 0
    for i in range(n):
        icm += (h1[i] * h2[(i + d) % n])
    icm/= n1*n2
    return icm

 

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    @param cipher : le text chiffré avec vigénére
    @param key_length : la taille de la clé avec laquelle le texte a était chiffré
    @return decalages : le tableau de decalage qui corespond au decalage de chaque colonne par rapport à la première colonne
    """
    decalages=[0]*key_length
    bloc = [[] for i in range(key_length)]
    for i in range(key_length):
        bloc[i]= [cipher[j] for j in range(i, len(cipher), key_length )]
    f1 = freq(''.join(bloc[0]))
    for i in range(1 , len(bloc)):
        ICM = [0]*26
        for d in range (26) : 
            f2 = freq(''.join(bloc[i]))
            ICM[d] = indice_coincidence_mutuelle(f1,f2,d)
        decalages[i] = ICM.index(max(ICM))
    return decalages


# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    @param cipher : le texte chiffré 
    @return : le texte cryptanalysé
    """
    key_length = longueur_clef(cipher)
    tab_decalage = tableau_decalages_ICM(cipher, key_length)
    textCesar = dechiffre_vigenere(cipher, tab_decalage)
    freq_max = lettre_freq_max(textCesar)
    return dechiffre_cesar(textCesar , (freq_max - 4) % 26)



################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(X,Y):
    """
    @param X : premier histogramme de fréquence
    @param Y : deuxieme histogramme de fréquence
    @return : correlation lineaire de Pearson des deux histogrammes 
    """
    n = len(X)
    assert n == len(Y), "Les listes doivent avoir la même longueur"
    mean_X = sum(X) / n
    mean_Y = sum(Y) / n
    s_X = math.sqrt(sum([(x - mean_X)**2 for x in X]) / (n-1))
    s_Y = math.sqrt(sum([(y - mean_Y)**2 for y in Y]) / (n-1))
    covariance = sum([(X[i] - mean_X) * (Y[i] - mean_Y) for i in range(n)]) / (n-1)
    correlation = covariance / (s_X * s_Y)
    return round(correlation,5)

def decale(chaine, n):
    # Convertit la chaîne de caractères en une liste de caractères
    liste_caracteres = list(chaine)
    # Décale chaque caractère de n positions vers la droite
    for i in range(len(liste_caracteres)):
        liste_caracteres[i] = chr((ord(liste_caracteres[i]) - 65 + n) % 26 + 65)
    # Convertit la liste de caractères en une chaîne de caractères et la renvoie
    return ''.join(liste_caracteres)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    @param cipher : le texte chiffré 
    @param key_length : la taille de la clé
    @return score,key : le tuple (moyenne des correlation maximisé ; la clé)
    """
    key=[0]*key_length
    l_corre=[0]*26
    max_corre=[]
    score = 0.0
    frequence("germinal_nettoye")
    bloc = [[] for i in range(key_length)]
    for i in range(key_length):
        bloc[i]= [cipher[j] for j in range(i, len(cipher), key_length )]
    
    for i in range(len(bloc)):
        for j in range(26):
            bloc_d=decale(bloc[i],j)
            l_corre[j] = correlation(freq(bloc_d) , freq_FR)
        
        if(l_corre.index(max(l_corre))!=0):
            key[i] = 26-l_corre.index(max(l_corre))
        else:
            key[i] = l_corre.index(max(l_corre))
        max_corre.append(max(l_corre))
    score = sum(max_corre)/len(max_corre)

    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    @param cipher : le texte chiffré 
    @return : le texte cryptanalisé 
    """
    score_l=[]
    key_l = []
    for i in range(1,20):
        score,key=clef_correlations(cipher,i)
        score_l.append(score)
        key_l .append(key)
    key = key_l[score_l.index(max(score_l))]
    return dechiffre_vigenere(cipher,key)





################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
