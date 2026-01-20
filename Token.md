⚠️ **ATTENTION CRITIQUE AVANT DE COMMENCER** ⚠️
**Ce token est littéralement la clé de ton compte.** Quiconque possède ce token peut se connecter à ton compte, changer tes skins, aller sur des serveurs en ton nom, et potentiellement accéder à tes infos Microsoft. **Ne le partage jamais, ni sur Discord, ni à un ami, ni sur un site web douteux.**

Voici la méthode via la console développeur (F12) sur le site officiel :

### Étape 1 : Se préparer

1. Ouvre ton navigateur (Chrome, Firefox, Edge).
2. Va sur le site officiel : **[minecraft.net/fr-fr/profile](https://www.google.com/search?q=https://www.minecraft.net/fr-fr/profile)**.
3. Connecte-toi avec ton compte Microsoft si ce n'est pas déjà fait.

### Étape 2 : Capturer le token

1. Une fois sur la page de profil, appuie sur **F12** pour ouvrir les outils de développement.
2. Clique sur l'onglet **Réseau** (ou **Network** en anglais) en haut de la fenêtre qui vient d'apparaître.
3. **Actualise la page** (F5) tout en laissant la fenêtre F12 ouverte. Tu vas voir plein de lignes apparaître.
4. Dans la barre de recherche "Filtre" (Filter) de l'onglet Réseau, tape : `profile`.
5. Tu devrais voir une ligne qui s'appelle `profile`. C'est une requête vers `api.minecraftservices.com`.
6. Clique sur cette ligne.

### Étape 3 : Trouver la ligne

1. À droite (ou en bas), regarde dans l'onglet **En-têtes** (ou **Headers**).
2. Cherche la section **En-têtes de requête** (ou **Request Headers**).
3. Cherche la ligne qui commence par **Authorization**.
4. La valeur ressemble à ceci :
`Bearer eyJhbGciOindmw... (une très longue suite de caractères)`

### Étape 4 : Copier

* S'il te demande juste le Token, copie uniquement ce qu'il y a **après** le mot `Bearer ` (sans l'espace).
