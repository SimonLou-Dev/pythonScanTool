from datetime import datetime

import requests
from jinja2 import Environment, FileSystemLoader
from tools.utils.logger import Logger, LogLevel


class WebModule:
    __logger: Logger
    __base_url: str
    __page_wordlist: str
    __user_wordlist: str
    __pass_wordlist: str
    __check_csp: bool = False
    __check_sensitive_pages: bool = False
    __check_sqli: bool = False
    __check_auth_bypass: bool = False
    __results = {
        "csp": None,
        "sensitive_pages": [],
        "sqli": [],
        "auth_bypass": [],
    }

    def __init__(self, logger: Logger, base_url: str, page_wordlist: str, user_wordlist: str, pass_wordlist: str):
        self.__logger = logger
        self.__base_url = base_url
        self.__page_wordlist = page_wordlist
        self.__user_wordlist = user_wordlist
        self.__pass_wordlist = pass_wordlist

    def run(self, enable_check_csp: bool = False, enable_check_sensitive_pages: bool=False, enable_check_sqli: bool=False, enable_check_auth_bypass: bool=False):
        self.__logger.info(f"Analyse de l'URL : {self.__base_url}")
        self.__logger.info(f"Options :")
        self.__logger.info(f" \t- Détecter l'absence ou la présence de CSP : {enable_check_csp}")
        self.__check_csp = enable_check_csp
        self.__logger.info(f" \t- Détecter les pages sensibles : {enable_check_sensitive_pages}")
        self.__check_sensitive_pages = enable_check_sensitive_pages
        self.__logger.info(f" \t- Détecter les injections SQL : {enable_check_sqli}")
        self.__check_sqli = enable_check_sqli
        self.__logger.info(f" \t- Détecter les contournements d'authentification POST : {enable_check_auth_bypass}")
        self.__check_auth_bypass = enable_check_auth_bypass

        if self.__check_csp:
            self.__get_csp()
        if self.__check_sensitive_pages:
            self.__get_sensitive_pages()
        if self.__check_sqli:
            self.__get_sqli()
        if self.__check_auth_bypass:
            self.__get_auth_bypass()
        self.__generate_report()

    def __get_csp(self):
        response = requests.get(self.__base_url)
        csp_header = response.headers.get("Content-Security-Policy")
        self.__results["csp"] = csp_header if csp_header else "None"
        status = "[+] CSP trouvée" if csp_header else "[-] Pas de CSP définie !"
        self.__logger.info(status)

    def __get_sensitive_pages(self):
        with open(self.__page_wordlist, "r") as f:
            for line in f:
                url = self.__base_url + line.strip()
                response = requests.get(url)
                if response.status_code == 200:
                    self.__results["sensitive_pages"].append(url)
                    self.__logger.info(f"[+] Page sensible trouvée : {url}")
                else:
                    self.__logger.info(f"[-] Page non trouvée : {url}")

    def __get_sqli(self):
        payloads = ["' OR 1=1 --", "admin' --", "' UNION SELECT 1,2,3 --"]
        for payload in payloads:
            for url in self.__results["sensitive_pages"]:
                payloaded_url = f"{url}?user={payload}"
                response = requests.get(payloaded_url)
                if "error" in response.text.lower() or "sql" in response.text.lower() or response.status_code == 200 or response.status_code == 500:
                    self.__results["sqli"].append({"url": url, "payload": payload})
                    self.__logger.info(f"[!] Potentielle injection SQL détectée à {url} avec : {payload}")

    def __get_auth_bypass(self):
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
                                self.__logger.info(f"[!] Authentification contournée à {url} avec {user}:{password}")

    def __generate_report(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        env = Environment(loader=FileSystemLoader("./tools/web"))
        template = env.get_template("report_template.html.j2")
        report_data = {
            "timestamp": timestamp,
            "base_url": self.__base_url,
            "results": self.__results,
        }
        self.__logger.info("Génération du rapport...")
        with open("web_report.html", "w") as f:
            f.write(template.render(report_data))
        self.__logger.info("Rapport généré dans ./web_report.html")