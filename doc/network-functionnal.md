# Documentation Fonctionnelle : Analyse des Paquets

Cette documentation fournit une vue d'ensemble fonctionnelle de l'analyse des paquets au sein de la classe `NetworkModule`.

## Initialisation

La classe `NetworkModule` permet l'analyse des paquets dans deux modes principaux :

- **Capture en direct (LIVE_CAP)** : Analyse des paquets en temps réel sur une interface réseau.
- **Fichier PCAP (FILE_PCAP)** : Lecture et analyse des paquets à partir d'un fichier `.pcap`.

Lors de l'initialisation :
- L'interface ou le fichier est validé.
- Les outils nécessaires comme les analyseurs de fréquence (via la classe `FrequencyAnalyser`) sont configurés pour surveiller les types de trafic spécifiques (ARP, ICMP, TCP, etc.).

## Modes d'Analyse

### 1. **Analyse de Fichier PCAP**

#### Fonctionnement :
- La méthode `__read_from_pcap()` lit tous les paquets d'un fichier PCAP via `scapy.all.rdpcap`.
- Chaque paquet est analysé par la méthode `__analyse_packet()`.

#### Exemple de Logique :
Pour chaque paquet, les conditions suivantes sont vérifiées :
- S'il contient un trafic HTTP, les URL et les mots de passe sont extraits.
- Si c'est un paquet UDP ou TCP, les ports et l'adresse source sont inspectés.
- Les paquets ARP ou ICMP sont également analysés pour détecter des scans.

Enfin, un rapport détaillé est généré en utilisant un template HTML.

### 2. **Capture en Direct**

#### Fonctionnement :
- La méthode `__read_live()` utilise `scapy.sendrecv.sniff` pour capturer les paquets en temps réel sur l'interface réseau spécifiée.
- Si l'option de sauvegarde est activée, les paquets capturés sont stockés dans un fichier PCAP.
- Les paquets capturés sont traités dans un thread séparé via la méthode `__capture_thread()`.

## Analyse des Paquets

### Fonction : `__analyse_packet(packet)`

Cette méthode traite chaque paquet capturé ou lu depuis un fichier.

#### Étapes Clés :
1. **HTTP** :
   - Recherche d'URLs et détection de mots de passe (en clair ou encodés en Base64).
   - Détection de scans bruteforce d'URLs si activé.

2. **UDP / TCP** :
   - Surveillance des ports et des adresses IP sources pour détecter des scans.

3. **ICMP** :
   - Détection des requêtes ICMP "ping".

4. **ARP** :
   - Détection des paquets ARP pour identifier les scans sur le réseau local.

#### Exemple de Conditions :
```python
if packet.haslayer(ARP) and packet[ARP].op == 1:
    self.__arp_fscanner.check({"src": packet[ARP].psrc}, int(packet.time))
    return

if packet.haslayer(ICMP) and packet[ICMP].type == 8:
    self.__ping_fscanner.check({"src": packet[IP].src}, int(packet.time))
    return
```

## Détection de Données Sensibles

### Fonction : `__detect_password_in_http(packet, url)`

- Recherche de mots-clés tels que `password`, `passwd`, etc., dans le contenu HTTP.
- Décodage des chaînes encodées en Base64 pour identifier des informations d'authentification sensibles.

Exemple :
```python
keywords = ["password", "passwd", "pwd", "pass"]
for keyword in keywords:
    if keyword in payload.lower():
        self.__passwordAndCred.append({"url": url, "secret": line.strip()})
```

## Génération de Rapport

### Fonction : `__generate_report()`

- Compile les résultats des analyseurs de fréquence (ARP, ICMP, etc.).
- Utilise un template HTML pour produire un rapport lisible contenant :
  - Les statistiques des analyses.
  - Les mots de passe et identifiants détectés.
  - Les options activées durant l'analyse.

Le rapport est sauvegardé sous le nom `report.html`.
