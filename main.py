import argparse

from tools.utils.logger import Logger



def main():
    parser = argparse.ArgumentParser(description="Boîte à outils de tests automatisés : Network et Web.")

    subparsers = parser.add_subparsers(dest="mode", help="Mode de fonctionnement : network ou web")

    # ============== Module Network ==============
    network_parser = subparsers.add_parser("network", help="Options liées au réseau")
    network_subparsers = network_parser.add_subparsers(dest="network_mode", help="Sous-options réseau")

    ## ============== Module Network : PCAP ==============
    pcap_parser = network_subparsers.add_parser("pcap", help="Analyse d'un fichier PCAP")
    pcap_parser.add_argument("file", help="Chemin vers le fichier PCAP")
    add_common_network_options(pcap_parser)

    # ============== Module Network : Live capture ==============
    iface_parser = network_subparsers.add_parser("iface", help="Capture en direct sur une interface réseau")
    iface_parser.add_argument("iface", help="Nom de l'interface réseau (ex: eth0)")
    iface_parser.add_argument("--save", "-s", action="store_true", help="Sauvegarder les paquets capturés dans un fichier PCAP")
    add_common_network_options(iface_parser)

    # ============== Module Web ==============

    web_parser = subparsers.add_parser("web", help="Options liées aux tests web")
    web_parser.add_argument("-u", "--url", help="URL cible pour les tests")
    web_parser.add_argument("-l", "--list", help="Fichier contenant une liste d'URLs")
    web_parser.add_argument("--csp", action="store_true", help="Activer le test des politiques CSP")
    web_parser.add_argument("--bruteforce", action="store_true", help="Activer le brute force des paths")
    web_parser.add_argument("--sql", action="store_true", help="Activer l'identification de données exploitables (SQLi)")

    parser.add_argument("--verbose", "-v", action="store_true", help="Activer le mode verbeux")

    # ============== Parsing ==============
    args = parser.parse_args()
    logger = Logger(args.verbose)
    # ============== Gestion des erreurs ==============
    if not args.mode:
        parser.print_help()
        return
    if args.mode == "network" and not args.network_mode:
        network_parser.print_help()
        return
    if args.mode == "web" and not (args.url or args.list):
        web_parser.print_help()
        return

    # ============== Lancement des modules ==============
    if args.mode == "network":
        if args.network_mode == "pcap":
            from tools.network.NetworkModule import NetworkModule, NetworkSourceType
            network = NetworkModule(logger, NetworkSourceType.FILE_PCAP, args.file)
            network.run(args.path_bf, args.http_passwords, args.http_credentials)
        elif args.network_mode == "iface":
            from tools.network.NetworkModule import NetworkModule, NetworkSourceType
            network = NetworkModule(logger, NetworkSourceType.LIVE_CAP, iface=args.iface, save=args.save)
            network.run()
    elif args.mode == "web":
        pass
        #from tools.web.WebModule import WebModule
        #web = WebModule(args.url, args.list)
        #web.run()



def add_common_network_options(parser):
    common_group = parser.add_argument_group("Options communes du module Network")
    common_group.add_argument("--path-bf", "-b", action="store_true", help="Détecter les scans bruteforce d'URLs")
    common_group.add_argument("--http-passwords", "-p", action="store_true", help="Détecter les mots de passe HTTP en clair")
    common_group.add_argument("--http-credentials", "-c", action="store_true", help="Détecter les credentials HTTP en base64")



if __name__ == "__main__":
    main()