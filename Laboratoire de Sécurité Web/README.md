# Laboratoire de Sécurité Web du Portail Étudiant

Application web complète développée avec Flask et SQLite pour un projet de fin d'études en cybersécurité.

## Informations du projet

| Élément | Détail |
|---|---|
| Établissement | EST Guelmim |
| Titre | Conception, audit de sécurité et remédiation d'une application web basée sur OWASP Top 10 |
| Réalisé par | Chol Makuol Garang Thok |
| Spécialité | Sécurité Informatique et Réseau |
| Objectif | Identifier, exploiter en environnement contrôlé, corriger et vérifier les vulnérabilités web courantes. |

Cette application contient deux versions du même portail étudiant :

- `/vuln/*` : routes volontairement vulnérables pour les tests en laboratoire.
- `/secure/*` : routes corrigées qui démontrent les bonnes pratiques de sécurité.

Ne déployez pas cette application publiquement. Utilisez-la uniquement en local.

## Fonctionnalités

- Connexion et inscription
- Tableau de bord étudiant
- Profil étudiant
- Recherche de modules
- Commentaires étudiants
- Upload de fichiers
- Panneau administrateur
- Journaux d'audit
- Version vulnérable et version sécurisée côte à côte

## Vulnérabilités incluses dans le mode vulnérable

| Vulnérabilité | Route vulnérable | Route sécurisée | Correction démontrée |
|---|---|---|---|
| Injection SQL | `/vuln/login`, `/vuln/search` | `/secure/login`, `/secure/search` | Requêtes paramétrées |
| XSS stocké | Commentaires dans `/vuln/dashboard` | Commentaires dans `/secure/dashboard` | Échappement de sortie et CSP |
| IDOR | `/vuln/profile?id=` | `/secure/profile?id=` | Autorisation au niveau objet |
| Contrôle d'accès cassé | `/vuln/admin` | `/secure/admin` | Autorisation basée sur les rôles |
| Stockage faible des mots de passe | Colonne `password_plain` | Colonne `password_hash` | Hachage des mots de passe avec Werkzeug |
| Upload non sécurisé | `/vuln/upload` | `/secure/upload` | Allowlist d'extensions et noms aléatoires |
| Manque de journalisation | Peu de logs côté vulnérable | Logs côté sécurisé | Journalisation d'audit |
| Mauvaise configuration sécurité | Routes vulnérables faibles | En-têtes sécurité | En-têtes HTTP de sécurité |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell
pip install -r requirements.txt
python app.py --init-db
python app.py
```

Ouvrez ensuite :

```text
http://127.0.0.1:5000
```

## Comptes de démonstration

| Mode | Nom d'utilisateur | Mot de passe | Rôle |
|---|---|---|---|
| Vulnérable | admin | admin123 | admin |
| Vulnérable | chol | chol123 | étudiant |
| Vulnérable | youssef | youssef123 | étudiant |
| Vulnérable | mustapha | mustapha123 | étudiant |
| Vulnérable | yassine | yassine123 | étudiant |
| Vulnérable | abderrahmane | abderrahmane123 | étudiant |
| Vulnérable | abdelkhalk | abdelkhalk123 | étudiant |
| Vulnérable | soulaimane | soulaimane123 | étudiant |
| Sécurisé | admin | Admin@12345 | admin |
| Sécurisé | chol | Chol@12345 | étudiant |
| Sécurisé | youssef | Youssef@12345 | étudiant |
| Sécurisé | mustapha | Mustapha@12345 | étudiant |
| Sécurisé | yassine | Yassine@12345 | étudiant |
| Sécurisé | abderrahmane | Abderrahmane@12345 | étudiant |
| Sécurisé | abdelkhalk | Abdelkhalk@12345 | étudiant |
| Sécurisé | soulaimane | Soulaimane@12345 | étudiant |

## Déroulement de démonstration conseillé

1. Commencer par le mode vulnérable.
2. Montrer le mauvais modèle de code dans `app.py`.
3. Démontrer l'impact dans le navigateur ou Burp Suite.
4. Passer au mode sécurisé.
5. Montrer le code corrigé.
6. Retester et prouver que l'attaque ne fonctionne plus.
7. Documenter les captures d'écran, la route affectée, le risque, l'impact, la correction et le résultat du retest.

## Plan conseillé pour le rapport

1. Introduction
2. Contexte et mapping OWASP Top 10
3. Architecture de l'application et environnement de laboratoire
4. Méthodologie de test
5. Résultats de l'audit et preuves d'exploitation
6. Implémentation des corrections
7. Retest et comparaison avant/après
8. Conclusion et perspectives
