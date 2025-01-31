🛠️ Boîte à outils de tests automatisés : Network et Web
📜 Description

Ce projet est une boîte à outils de tests automatisés dédiée à la capture et à l'analyse de trafic réseau 🌐, ainsi qu'aux tests de vulnérabilités sur des applications web 🔍. Il permet de réaliser des actions telles que :

    🚨 Capture de paquets réseau et analyse de fichiers PCAP.
    🕵️‍♂️ Détection de trafic suspect (comme le bruteforce d'URLs ou les mots de passe HTTP en clair).
    🛡️ Tests de vulnérabilités sur des applications web (test de politique CSP, recherche de pages vulnérables comme admin.php, backup, et identification de vulnérabilités potentielles comme l'injection SQL).

⚙️ Fonctionnalités principales
🌐 Module Network

    📡 Capture de paquets réseau via une interface réseau ou un fichier PCAP.
    📜 Analyse des logs Apache/Nginx pour identifier des comportements suspects.
    🔓 Détection de scans bruteforce, de mots de passe en clair HTTP, et de credentials HTTP en base64.
    💾 Enregistrement des paquets capturés dans un fichier PCAP.

💻 Module Web

    🛠️ Tests automatisés de vulnérabilités sur des applications web.
    🔒 Vérification des politiques CSP via requests.
    🚪 Identification de pages vulnérables comme admin.php, backup.
    💥 Identification de données exploitables, par exemple l'injection SQL (SQLi).

📊 Tableau de bord HTML

    🖥️ Génération de rapports et d'indicateurs interactifs avec jinja pour une présentation visuelle des résultats des tests.

📦 Installation
🚀 Prérequis

    Python 3.x
    Bibliothèques Python :
        scapy pour la capture de paquets réseau.
        requests pour effectuer des requêtes HTTP.
        termcolor pour l'affichage en couleur dans le terminal.
        jinja2 pour générer des rapports en HTML.

🧑‍💻 Installation des dépendances

    Clonez le repository sur votre machine locale :

git clone https://github.com/SimonLou-Dev/pythonScanTool.git
cd pythonScanTool

Installez les dépendances nécessaires :

    pip install -r requirements.txt

🚀 Utilisation

L'outil fonctionne avec argparse pour la gestion des commandes et des options. Voici un aperçu de son utilisation.
🎮 Lancer le programme

Pour lancer l'outil, utilisez la commande suivante :

python main.py --verbose

Cela vous permet d'afficher des logs détaillés en mode verbeux.
📝 Options disponibles

L'outil prend en charge plusieurs modes et sous-options pour les modules réseau et web.
🌐 Mode network

Ce mode permet d'effectuer des analyses de réseau.

python main.py network [pcap | iface ] [options]

    pcap : Analyse d'un fichier PCAP.
        Exemple : python main.py network pcap /path/to/file.pcap

    iface : Capture de paquets en direct à partir d'une interface réseau.
        Exemple : python main.py network iface eth0 --save


💻 Mode web

Ce mode permet de réaliser des tests automatisés sur des applications web.

python main.py web [options]

    URL cible : URL de l'application web à tester.
        Exemple : python main.py web -u http://example.com

    Options supplémentaires :
        CSP : Activer le test des politiques CSP (--csp).
        Bruteforce : Tester la possibilité de brute-forcer des chemins d'URL (--bruteforce).
        SQL Injection : Identifier des vulnérabilités potentielles liées à l'injection SQL (--sql).

⚙️ Mode Verbeux

Le mode verbeux permet d'afficher des messages détaillés de log pour chaque action. Vous pouvez l'activer avec l'option --verbose ou -v.

python main.py --verbose

📑 Exemple d'exécution

python main.py network pcap /path/to/file.pcap --verbose

Cela lance l'analyse du fichier PCAP avec des logs détaillés.
🖥️ Exemple d'un rapport HTML

Après avoir exécuté un test, vous pouvez générer un rapport HTML avec les résultats sous forme visuelle. Ce rapport est généré à partir des templates jinja et contient des graphiques et des informations sur les vulnérabilités détectées.
🤝 Contribution

    Fork le repository.
    Crée une branche (git checkout -b feature/ma-fonctionnalité).
    Commit tes changements (git commit -am 'Ajoute une fonctionnalité').
    Pousse sur ta branche (git push origin feature/ma-fonctionnalité).
    Ouvre une pull request.

📄 License

Ce projet est sous licence MIT. Consultez le fichier LICENSE pour plus d'informations.
