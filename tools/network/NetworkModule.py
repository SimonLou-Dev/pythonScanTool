from enum import Enum

import psutil
import scapy.sendrecv
import threading
from scapy.layers.inet import IP

from tools.utils.logger import Logger, LogLevel


class NetworkSourceType(Enum):
    LOG_NGINX = 1
    LOG_APACHE = 2
    LIVE_CAP = 3
    FILE_PCAP = 4

    def __str__(self):
        return self.name.replace("_", " ").title()

class NetworkModule:
    __mode: NetworkSourceType
    __file: str | None
    __iface: str | None
    __save: bool = False
    __logger: Logger

    def __init__(self, logger: Logger, mode: NetworkSourceType, file: str | None = None, iface: str | None = None, save: bool = False):
        self.__mode = mode
        self.__logger = logger
        if mode == NetworkSourceType.LOG_NGINX or mode == NetworkSourceType.LOG_APACHE:
            self.__file = file
        elif mode == NetworkSourceType.LIVE_CAP:
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
        self.__logger.info(f" \t- Détecter les mots de passe HTTP en clair : {enable_http_passwords}")
        self.__logger.info(f" \t- Détecter les credentials HTTP en base64 : {enable_http_credentials}")
        self.__logger.info(f" \t- Mode : {self.__mode}")

        if self.__mode == NetworkSourceType.LOG_NGINX or self.__mode == NetworkSourceType.LOG_APACHE:
            self.__read_from_logs()
        elif self.__mode == NetworkSourceType.LIVE_CAP:
            self.__read_live()
        elif self.__mode == NetworkSourceType.FILE_PCAP:
            self.__read_from_pcap()

    # Reader methods
    ## Read from pcap
    def __read_from_pcap(self):
        self.__logger.info(f"Analyse du fichier pcap : {self.__file}")

        pass

    def __read_from_logs(self):
        self.__logger.info(f"Analyse du fichier de logs : {self.__file}")

        pass

    ## Live capture
    def __read_live(self):
        self.__logger.info(f"Capture en direct sur l'interface {self.__iface}")
        if self.__save:
            self.__logger.info(f"Les paquets capturés seront enregistrés dans un fichier pcap")
        self.__logger.input_and_log("Appuyez sur ENTER pour démarrer et arrêter la capture...\n", LogLevel.INFO)
        self.__logger.info("Démarrage de la capture...")
        capture_thread = threading.Thread(target=self.__capture_thread)
        capture_thread.daemon = True  # Permet au thread de s'arrêter quand le programme principal termine
        capture_thread.start()
        input("")
        # Attente de l'utilisateur pour appuyer sur ENTER
        self.__logger.info("Arrêt de la capture...")
        pass

    ## Live capture thread
    def __capture_thread(self):
        scapy.sendrecv.sniff(iface=self.__iface, prn=self.__analyse_packet)

    ## Analyser
    def __analyse_packet(self, packet):
        if self.__save and self.__mode == NetworkSourceType.LIVE_CAP:
            scapy.sendrecv.wrpcap("capture.pcap", packet, append=True)

        if packet.haslayer(IP):
            ip_packet = packet[IP]
            if ip_packet.proto == 1:
                self.__logger.debug("C'est un paquet ICMP")
            elif ip_packet.proto == 6:
                self.__logger.debug("C'est un paquet ICMP")
            elif ip_packet.proto == 17:
                self.__logger.debug("C'est un paquet ICMP")
            else:
                self.__logger.debug("Protocole IP non identifié")

        else:
            self.__logger.debug("Protocole IP non identifié")
        pass