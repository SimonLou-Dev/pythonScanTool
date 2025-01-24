# Documentation Fonctionnelle : Analyse des Paquets

Cette documentation présente les fonctionnalités de la classe `NetworkModule`, qui permet l'analyse des paquets réseau dans différents contextes. Elle prend en charge deux modes d'analyse : en temps réel (capture en direct) et à partir d'un fichier PCAP.

## Table des matières

1. [Introduction](#introduction)
2. [Modes d'Analyse](#modes-danalyse)
   - [Analyse de Fichier PCAP](#analyse-de-fichier-pcap)
   - [Capture en Direct](#capture-en-direct)
3. [Analyse des Paquets](#analyse-des-paquets)
4. [Détection de Données Sensibles](#détection-de-données-sensibles)
5. [Génération de Rapport](#génération-de-rapport)

## Introduction

Le module `NetworkModule` permet l'analyse de paquets dans deux modes principaux :
- **Capture en direct (LIVE_CAP)** : Analyse des paquets en temps réel sur une interface réseau.
- **Fichier PCAP (FILE_PCAP)** : Lecture et analyse des paquets à partir d'un fichier `.pcap`.

Lors de l'initialisation, l'interface ou le fichier est validé et les outils nécessaires (comme les analyseurs de fréquence via la classe `FrequencyAnalyser`) sont configurés pour surveiller différents types de trafic tels que ARP, ICMP, TCP, etc.

## Modes d'Analyse

### 1. **Analyse de Fichier PCAP**

#### Fonctionnement :
- La méthode `__read_from_pcap()` lit tous les paquets d'un fichier PCAP via `scapy.all.rdpcap`.
- Chaque paquet est ensuite analysé par la méthode `__analyse_packet()`.

#### Exemple de Logique :
Pour chaque paquet, les conditions suivantes sont vérifiées :
- Si le paquet contient du trafic HTTP, les URL et mots de passe sont extraits.
- Si c'est un paquet UDP ou TCP, les ports et adresses source sont analysés.
- Les paquets ARP ou ICMP sont également vérifiés pour détecter des scans.

Un rapport détaillé est généré au format HTML.

### 2. **Capture en Direct**

#### Fonctionnement :
- La méthode `__read_live()` utilise `scapy.sendrecv.sniff` pour capturer les paquets en temps réel sur l'interface réseau spécifiée.
- Si l'option de sauvegarde est activée, les paquets capturés sont stockés dans un fichier PCAP.
- Les paquets capturés sont ensuite traités dans un thread séparé via la méthode `__capture_thread()`.

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

### Détection de Données Sensibles
### Fonction : `__detect_password_in_http(packet, url)`

    Recherche de mots-clés tels que password, passwd, etc., dans le contenu HTTP.
    Décodage des chaînes encodées en Base64 pour identifier des informations d'authentification sensibles.

Exemple :
```python
keywords = ["password", "passwd", "pwd", "pass"]
for keyword in keywords:
    if keyword in payload.lower():
        self.__passwordAndCred.append({"url": url, "secret": line.strip()})
```
### Génération de Rapport
### Fonction : `__generate_report()`

    Compile les résultats des analyseurs de fréquence (ARP, ICMP, etc.).
    Utilise un template HTML pour produire un rapport lisible contenant :
        Les statistiques des analyses.
        Les mots de passe et identifiants détectés.
        Les options activées durant l'analyse.

Le rapport est sauvegardé sous le nom `report.html`.
---
### Points Clés supplémentaires
**HTTP, TCP, ARP, ICMP - Prise en compte des Requêtes uniquement**

    Pour l'analyse des paquets HTTP, TCP, ARP et ICMP, seuls les paquets contenant des requêtes sont pris en compte.

**Vérification TCP pour les Paquets HTTP**

    Pour les paquets TCP, une vérification est effectuée pour s'assurer que le paquet ne contient pas des données HTTP, car scapy peut parfois ne pas parser correctement les paquets HTTP. Le contrôle est fait sur le flag SYN des paquets TCP afin de détecter les nouvelles connexions.

Exemple de vérification dans la méthode `__analyse_packet` :
```python
if packet.haslayer(TCP) and packet.haslayer(IP) and packet[TCP].flags == 'S':
    if self.__analyse_tcp_packet(packet): return
    self.__namp_fscanner.check({"src": packet[IP].src, "value": "TCP"}, int(packet.time))
    return
```

## Test
Exemple de fichier example.pcap

Le fichier example.pcap contient une capture de paquets réalisée dans les conditions suivantes :

    Scan ARP sur le réseau local : Un scan ARP a été effectué sur le réseau 192.168.1.0/24 pour identifier tous les hôtes du réseau. Cela permet de cartographier les appareils connectés. Le réseau contient 255 hôtes.

    Commande utilisée :

```bash
sudo arp-scan --interface=eth0 192.168.1.0/24 -w capture.pcap
```

Scan Nmap sur le réseau avec -T3 : Un scan Nmap de type -T3 a été effectué sur l'ensemble du réseau local pour découvrir les hôtes et services actifs. Ce scan est plus lent et discret.

Commande utilisée :
```bash
sudo nmap -T3 192.168.1.0/24
```
Scan Nmap sur un hôte spécifique avec -T3 -p- : Un scan Nmap de type -T3 a été réalisé sur l'hôte 192.168.1.59 pour scanner tous les ports (-p-) et identifier les services actifs.

Commande utilisée :
```bash
sudo nmap -T3 -p- 192.168.1.59
```
Scan Gobuster en parallèle : Un scan de brute force des chemins web a été effectué en parallèle à l'aide de Gobuster pour tester les URL accessibles sur un serveur web local. Ce scan utilise une liste de mots pour tester les chemins d'accès.

Commande utilisée :
```bash
    gobuster dir -u http://192.168.1.59 -w /path/to/wordlist.txt
```
Tous ces scans ont été exécutés simultanément pour simuler une analyse réseau complète dans un environnement local. La capture des paquets a été enregistrée dans le fichier example.pcap, qui contient ainsi les résultats de ces différentes analyses réseau.

### Préparation du fichier example.pcap
```bash
python3 main.py network iface eth0 -sbpc
```

### Chargement du Fichier PCAP
```bash
python3 main.py network pcap ./example.pcap -bpc
```