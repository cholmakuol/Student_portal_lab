# Guide de Test

Utilisez ce guide uniquement contre l'instance locale du laboratoire : `http://127.0.0.1:5000`.

## 1. Injection SQL

Routes affectées :

- `/vuln/login`
- `/vuln/search`

Faiblesse de sécurité :

- La requête SQL est construite par concaténation directe de l'entrée utilisateur.

Routes corrigées :

- `/secure/login`
- `/secure/search`

Correction :

- Utiliser des requêtes SQL paramétrées.
- Restreindre les résultats de recherche à l'utilisateur authentifié.

Preuves à capturer :

- Capture de la requête vulnérable affichée sur la page.
- Capture du comportement de connexion ou de recherche avant correction.
- Capture du mode sécurisé qui rejette la même entrée.

## 2. XSS stocké

Route affectée :

- `/vuln/dashboard`

Faiblesse de sécurité :

- Le commentaire est affiché avec Jinja `safe`, donc le HTML est exécuté au lieu d'être échappé.

Route corrigée :

- `/secure/dashboard`

Correction :

- Afficher le contenu contrôlé par l'utilisateur avec l'échappement Jinja par défaut.
- Ajouter un en-tête Content Security Policy sur les routes sécurisées.

Preuves à capturer :

- Capture montrant l'exécution ou le rendu dangereux du commentaire.
- Capture montrant la même entrée affichée comme simple texte dans le mode sécurisé.

## 3. IDOR

Route affectée :

- `/vuln/profile?id=`

Faiblesse de sécurité :

- La route fait confiance au paramètre `id` et ne vérifie pas si l'utilisateur connecté possède le profil demandé.

Route corrigée :

- `/secure/profile?id=`

Correction :

- Convertir `id` en entier.
- Autoriser l'accès seulement si l'utilisateur est admin ou propriétaire du profil demandé.
- Journaliser les tentatives bloquées.

Preuves à capturer :

- Youssef qui affiche le profil de Mustapha dans le mode vulnérable.
- Mode sécurisé qui retourne 403 pour la même action.

## 4. Contrôle d'accès cassé

Route affectée :

- `/vuln/admin`

Faiblesse de sécurité :

- Tout utilisateur authentifié dans le mode vulnérable peut accéder au panneau administrateur.

Route corrigée :

- `/secure/admin`

Correction :

- Appliquer une autorisation basée sur les rôles.
- Masquer le lien admin pour les utilisateurs non-admin.
- Retourner 403 lorsqu'un étudiant tente l'accès.

## 5. Upload de fichier non sécurisé

Route affectée :

- `/vuln/upload`

Faiblesse de sécurité :

- Toutes les extensions sont acceptées.
- Le nom original du fichier est réutilisé.

Route corrigée :

- `/secure/upload`

Correction :

- Autoriser uniquement des extensions à faible risque.
- Générer un nom de fichier aléatoire avec UUID.
- Appliquer une taille maximale.
- Journaliser les uploads bloqués.

## 6. Stockage faible des mots de passe

Zone affectée :

- L'inscription vulnérable stocke les mots de passe en clair dans `password_plain`.
- Le panneau admin vulnérable affiche les mots de passe en clair.

Zone corrigée :

- L'inscription sécurisée stocke uniquement `password_hash`.
- Le panneau admin sécurisé n'affiche jamais les mots de passe.

Correction :

- Utiliser un hachage robuste des mots de passe.
- Ne jamais stocker ou afficher les mots de passe en clair.
