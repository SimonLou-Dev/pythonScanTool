from datetime import datetime
from enum import Enum

import psutil
import scapy.sendrecv
from scapy.all import rdpcap, Raw
import threading
import re
import base64
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP
from jinja2 import Environment, FileSystemLoader

from tools.utils.logger import Logger, LogLevel
from tools.utils.frequencyAnalyser import FrequencyAnalyser


class NetworkSourceType(Enum):
    LIVE_CAP = 0
    FILE_PCAP = 1

    def __str__(self):
        return self.name.replace("_", " ").title()

class NetworkModule:
    __mode: NetworkSourceType
    __file: str | None = None
    __iface: str | None = None
    __save: bool = False
    __logger: Logger
    __namp_fscanner: FrequencyAnalyser
    __fuzz_fscanner: FrequencyAnalyser
    __ping_fscanner: FrequencyAnalyser
    __arp_fscanner: FrequencyAnalyser
    __path_bf: bool = False
    __find_pass: bool = False
    __find_cred: bool = False
    __pcap_file: str = ""

    __passwordAndCred: list[dict[str, str]] = []

    def __init__(self, logger: Logger, mode: NetworkSourceType, file: str | None = None, iface: str | None = None, save: bool = False):
        self.__mode = mode
        self.__logger = logger
        if mode == NetworkSourceType.LIVE_CAP:
            self.__iface = self.__check_iface(iface)
            self.__save = save
        elif mode == NetworkSourceType.FILE_PCAP:
            self.__file = file

    # Checker method

    def __check_iface(self, iface: str | None) -> str:
        interfaces = psutil.net_if_addrs()
        if iface is None or iface not in interfaces:
            self.__logger.error("Interface non valide - Interfaces disponibles :")
            for interface in interfaces:
                self.__logger.error(f" - {interface}")
            exit(1)
        return iface

    # Runner method
    def run(self, enable_path_bf : bool = False, enable_http_passwords : bool = False, enable_http_credentials : bool = False):
        self.__logger.info(f"Options :")
        self.__logger.info(f" \t- Détecter les scans bruteforce d'URLs : {enable_path_bf}")
        self.__path_bf = enable_path_bf
        self.__logger.info(f" \t- Détecter les mots de passe HTTP en clair : {enable_http_passwords}")
        self.__find_pass = enable_http_passwords
        self.__logger.info(f" \t- Détecter les credentials HTTP en base64 : {enable_http_credentials}")
        self.__find_cred = enable_http_credentials
        self.__logger.info(f"Mode : {self.__mode}")

        self.__arp_fscanner = FrequencyAnalyser(self.__logger)
        self.__fuzz_fscanner = FrequencyAnalyser(self.__logger)
        self.__namp_fscanner = FrequencyAnalyser(self.__logger)
        self.__ping_fscanner = FrequencyAnalyser(self.__logger)


        if self.__mode == NetworkSourceType.LIVE_CAP:
            self.__read_live()
        elif self.__mode == NetworkSourceType.FILE_PCAP:
            self.__read_from_pcap()


    # Reader methods
    ## Read from pcap
    def __read_from_pcap(self):
        self.__logger.info(f"Analyse du fichier pcap : {self.__file}")
        scapy_cap = rdpcap(self.__file)
        self.__logger.info(f"Nombre de paquets : {len(scapy_cap)}")
        for packet in scapy_cap:
            self.__analyse_packet(packet)
        self.__generate_report()

    def __create_pcap_file(self) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return f"capture_{timestamp}.pcap"


    ## Live capture
    def __read_live(self):
        self.__logger.info(f"Capture en direct sur l'interface {self.__iface}")
        if self.__save:
            self.__pcap_file = self.__create_pcap_file()
            self.__logger.info(f"Les paquets capturés seront enregistrés dans le fichier {self.__pcap_file}")
        self.__logger.input_and_log("Appuyez sur ENTER pour démarrer et arrêter la capture...\n", LogLevel.INFO)
        self.__logger.info("Démarrage de la capture...")
        capture_thread = threading.Thread(target=self.__capture_thread)
        capture_thread.daemon = True  # Permet au thread de s'arrêter quand le programme principal termine

        capture_thread.start()
        input("")
        # Attente de l'utilisateur pour appuyer sur ENTER
        self.__logger.info("Arrêt de la capture...")
        self.__generate_report()
        pass

    ## Live capture thread
    def __capture_thread(self):
        scapy.sendrecv.sniff(iface=self.__iface, prn=self.__analyse_packet)

    ## Analyser
    def __analyse_packet(self, packet):

        #print("ARP", self.__arp_fscanner.result())
        #print("ICMP", self.__ping_fscanner.result())




        if self.__save and self.__mode == NetworkSourceType.LIVE_CAP:
            scapy.sendrecv.wrpcap(self.__pcap_file, packet, append=True)
        if packet.haslayer(HTTPRequest) and packet.haslayer(IP): # Quand scapy arrive à déconstruire le paquet HTTP
            host = packet[HTTPRequest].Host.decode()
            url = packet[HTTPRequest].Path.decode()
            self.__detect_password_in_http(packet, host + url)
            self.__logger.debug(f"Capture d'un packet HTTP de {packet[IP].src} sur le site {host}")
            if self.__path_bf is True:
                self.__fuzz_fscanner.check({"src": packet[IP].src, "value": host}, int(packet.time))
            return
        if packet.haslayer(TCP) and packet.haslayer(IP) and "P" in packet[TCP].flags: # Si c'est un paquet SYN

            if self.__analyse_tcp_packet(packet): return  # Le parser  scapy ne marche pour l'HTTPS et l'HTTP (pour le curl) alors on improvise
            self.__logger.debug(f"Capture d'un packet TCP de {packet[IP].src} sur le port {packet[TCP].dport}")
            self.__namp_fscanner.check({"src": packet[IP].src, "value": "TCP-UDP"}, int(packet.time))
            return
        if packet.haslayer(UDP) and packet.haslayer(IP):
            self.__logger.debug(f"Capture d'un packet UDP de {packet[IP].src} sur le port {packet[UDP].dport}")
            self.__namp_fscanner.check({"src": packet[IP].src, "value": "TCP-UDP"}, int(packet.time))
            return
        if packet.haslayer(ICMP) and packet.haslayer(IP) and packet[ICMP].type == 8: #Si c'est une requête ICMP
            self.__logger.debug(f"Capture d'un packet ICMP de {packet[IP].src}")
            self.__ping_fscanner.check({"src": packet[IP].src, "value": "ICMP"}, int(packet.time))
            return
        if packet.haslayer(ARP) and packet[ARP].op == 1: # Si c'est un paquet ARP
            self.__logger.debug(f"Capture d'un packet ARP de {packet[ARP].psrc}")
            self.__arp_fscanner.check({"src": packet[ARP].psrc, "value": "ARP"}, int(packet.time))
            return

    ## Analyser les paquets TCP au cas ou ça soit du HTTP(S)
    def __analyse_tcp_packet(self, packet) -> bool:
        if packet[TCP].payload:
            raw_data = packet[TCP].payload.load
            if b"HTTP" in raw_data or b"HTTPS" in raw_data:
                self.__logger.debug(f"Capture d'un packet HTTP de {packet[IP].src}")
                try:
                    raw_str = raw_data.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    return False  # Skip if the data can't be decoded
                hostname = "?"
                if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)", raw_str): # Les requêtes HTTP commencent par une méthode
                    # Try to extract the Host header using a regex pattern
                    host_match = re.search(r"Host: ([^\r\n]+)", raw_str)
                    if host_match:
                        hostname = host_match.group(1)
                        self.__logger.debug(f"Capture d'un packet HTTP de  {packet[IP].src} à destination de: {hostname}")
                    else:
                        self.__logger.debug(f"Capture d'un packet HTTP de {packet[IP].src} à destination de ?")
                    if self.__path_bf:
                        self.__fuzz_fscanner.check({"src": packet[IP].src, "value": hostname}, int(packet.time))
                    if b"HTTP" in raw_data:
                        self.__detect_password_in_http(packet, packet[IP].src)
                    return True

            # Si ce n'est pas une requête alors c'est une réponse
            self.__logger.debug(f"Capture d'un packet HTTP response à destination de {packet[IP].dst} en provenance de {packet[IP].src}")
            return True

        return False

    ## Détection dans le HTTP
    def __detect_password_in_http(self, packet, url):
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")  # Décoder sans lever d'erreurs
            if self.__find_pass:
                keywords = ["password", "passwd", "pwd", "pass"]
                for keyword in keywords:
                    if keyword in payload.lower():
                        lines = payload.split("\n")
                        for line in lines:
                            if keyword in line.lower():
                                self.__passwordAndCred.append({"url": url, "secret": line.strip()})


            base64_matches = re.findall(r"[A-Za-z0-9+/=]{20,}", payload)  # Motif pour chaînes Base64
            if self.__find_cred:
                for match in base64_matches:
                    try:
                        decoded = base64.b64decode(match).decode(errors="ignore")
                        if any(kw in decoded.lower() for kw in keywords):
                            self.__passwordAndCred.append({"url": url, "secret": decoded.strip()})
                    except Exception:
                        pass  # Ignorer les erreurs de décodage

    # Génération du rapport
    def __generate_report(self):
        self.__logger.info("Préparation du rapport...")
        env = Environment(loader=FileSystemLoader("./tools/network"))
        template = env.get_template("report_template.html.j2")
        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mode": {
                "value": self.__mode,
                "number": self.__mode.value
            },
            "interface": self.__iface,
            "pcap_file": self.__file,
            "options": {
                "fuzzing": self.__path_bf,
                "passwords": self.__find_pass,
                "creds": self.__find_cred
            },
            "results": {
                "creds": self.__passwordAndCred,
                "arp_scan": self.__arp_fscanner.result(),
                "icmp_scan": self.__ping_fscanner.result(),
                "port_scan": self.__namp_fscanner.result(),
                "fuzz_scan": self.__fuzz_fscanner.result()
            },
            "save": {
                "state": self.__save,
                "file": self.__pcap_file
            }
        }
        self.__logger.info("Génération du rapport...")
        with open("report.html", "w") as f:
            f.write(template.render(report_data))
        self.__logger.info("Rapport généré dans ./report.html")
        pass