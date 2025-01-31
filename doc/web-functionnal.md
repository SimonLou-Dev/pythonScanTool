# Documentation Fonctionnelle : Tests de vulnérabilités web

Cette documentation présente les fonctionnalités de la classe `WebModule`, qui permet l'analyse de vulnérabilités sur une application web. Le module permet d'identifier des failles potentielles comme l'absence de CSP, la présence de pages sensibles, les injections SQL et les contournements d'authentification.

## Table des matières

- [Documentation Fonctionnelle : Tests de vulnérabilités web](#documentation-fonctionnelle--tests-de-vulnérabilités-web)
  - [Table des matières](#table-des-matières)
  - [Introduction](#introduction)
  - [Fonctionnalités](#fonctionnalités)
    - [1. Détection de l'Absence de CSP](#1-détection-de-labsence-de-csp)
      - [Fonctionnement :](#fonctionnement-)
    - [2. Détection de Pages Sensibles](#2-détection-de-pages-sensibles)
      - [Fonctionnement :](#fonctionnement--1)
    - [3. Détection des Injections SQL](#3-détection-des-injections-sql)
      - [Fonctionnement :](#fonctionnement--2)
    - [4. Détection des Contournements d'Authentification](#4-détection-des-contournements-dauthentification)
      - [Fonctionnement :](#fonctionnement--3)
  - [Génération de Rapport](#génération-de-rapport)
    - [Fonction : `__generate_report()`](#fonction--__generate_report)
      - [Fonctionnement :](#fonctionnement--4)
  - [Utilisation](#utilisation)
    - [Exemple de Commande :](#exemple-de-commande-)
    - [Paramètres :](#paramètres-)
    - [Sortie :](#sortie-)

## Introduction

Le module `WebModule` permet d'analyser un site web en identifiant plusieurs types de vulnérabilités en utilisant des fichiers de dictionnaires pour les pages, utilisateurs et mots de passe.

Lors de l'exécution, il peut activer une ou plusieurs analyses :
- **Détection de CSP** : Vérifie la présence d'un en-tête `Content-Security-Policy`.
- **Recherche de pages sensibles** : Teste des chemins web connus.
- **Test d'injections SQL** : Effectue des tests d'injections sur les pages détectées.
- **Tentative de contournement d'authentification** : Teste des combinaisons utilisateur/mot de passe sur les pages sensibles.

## Fonctionnalités

### 1. Détection de l'Absence de CSP

#### Fonctionnement :
- Envoie une requête `GET` à l'URL cible.
- Vérifie si l'en-tête `Content-Security-Policy` est présent.
- Enregistre le résultat et affiche un message d'alerte en cas d'absence.

Exemple :
```python
response = requests.get(self.__base_url)
csp_header = response.headers.get("Content-Security-Policy")
self.__results["csp"] = csp_header if csp_header else "None"
```

### 2. Détection de Pages Sensibles

#### Fonctionnement :
- Charge un fichier contenant une liste de chemins de pages web.
- Envoie une requête `GET` pour chaque chemin.
- Si une réponse `200 OK` est retournée, la page est considérée comme accessible et potentiellement sensible.

Exemple :
```python
with open(self.__page_wordlist, "r") as f:
    for line in f:
        url = self.__base_url + line.strip()
        response = requests.get(url)
        if response.status_code == 200:
            self.__results["sensitive_pages"].append(url)
```

### 3. Détection des Injections SQL

#### Fonctionnement :
- Pour chaque page sensible trouvée, injecte une liste de charges SQL courantes.
- Vérifie si la réponse contient une erreur SQL ou si une réponse anormale est retournée (`500`, `200` suspect, etc.).
- Enregistre les URL vulnérables et les charges utilisées.

Exemple :
```python
payloads = ["' OR 1=1 --", "admin' --", "' UNION SELECT 1,2,3 --"]
for payload in payloads:
    for url in self.__results["sensitive_pages"]:
        payloaded_url = f"{url}?user={payload}"
        response = requests.get(payloaded_url)
        if "error" in response.text.lower() or "sql" in response.text.lower() or response.status_code == 500:
            self.__results["sqli"].append({"url": url, "payload": payload})
```

### 4. Détection des Contournements d'Authentification

#### Fonctionnement :
- Pour chaque page sensible trouvée, tente de s'authentifier avec une liste d'utilisateurs et de mots de passe.
- Vérifie si la réponse indique un accès réussi (`200` ou `302`).
- Enregistre les combinaisons fonctionnelles.

Exemple :
```python
for url in self.__results["sensitive_pages"]:
    with open(self.__user_wordlist, "r") as f_users:
        for user in f_users:
            user = user.strip()
            with open(self.__pass_wordlist, "r") as f_pass:
                for password in f_pass:
                    password = password.strip()
                    response = requests.post(url, data={"login": user, "password": password})
                    if response.status_code in (200, 302):
                        self.__results["auth_bypass"].append({"url": url, "user": user, "password": password})
```

## Génération de Rapport

### Fonction : `__generate_report()`

#### Fonctionnement :
- Compile tous les résultats des analyses.
- Génère un rapport HTML contenant :
  - Date et heure de l'analyse.
  - Résumé des vulnérabilités détectées.
  - Pages vulnérables et charges utilisées.
- Utilise un template Jinja2 pour structurer le rapport.

Exemple :
```python
env = Environment(loader=FileSystemLoader("./tools/web"))
template = env.get_template("report_template.html.j2")
report_data = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "base_url": self.__base_url, "results": self.__results}
with open("web_report.html", "w") as f:
    f.write(template.render(report_data))
```

## Utilisation

### Exemple de Commande :
```bash
python3 main.py web https://example.com page_wordlist.txt user_wordlist.txt pass_wordlist.txt --csp --sensitive --sqli --auth
```

### Paramètres :
- `base_url` : URL de la cible.
- `page_wordlist` : Liste des pages sensibles à tester.
- `user_wordlist` : Liste des noms d'utilisateur.
- `pass_wordlist` : Liste des mots de passe.
- `--csp` : Active la détection de CSP.
- `--sensitive` : Active la recherche de pages sensibles.
- `--sqli` : Active la détection d'injections SQL.
- `--auth` : Active les tests de contournement d'authentification.

### Sortie :
Le rapport généré est stocké sous le nom `web_report.html`.