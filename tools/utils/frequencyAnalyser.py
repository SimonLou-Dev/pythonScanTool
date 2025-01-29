
from tools.utils.logger import Logger, LogLevel


class FrequencyAnalyser:
    __lastSeconds: int = 0
    __flagOccurences: int = 5 #Number of occurences par sec

    __logger: Logger

    def __init__(self, logger: Logger, flag_occurences: int = 5):
        self.__flagOccurences = flag_occurences
        self.__logger = logger
        self.__lastSecondsOccurences: list[dict[str, str]] = []
        self.__flagged: list[dict[str, str]] = []

    def check(self, key: dict[str, str], time: int):
        if time != self.__lastSeconds:
            self.__check_occurences()
            self.__lastSeconds = time
            self.__lastSecondsOccurences.clear()
        self.__lastSecondsOccurences.append(key)

    def __check_occurences(self):
        localF =  []
        for key in self.__lastSecondsOccurences:
            existing = next((item for item in localF if item["src"] == key.get("src")), None)
            if existing:
                existing["occ"] += 1
            else:
                localF.append({
                    "src": key.get("src"),
                    "value": key.get("value"),
                    "occ": 1,
                })
        self.__push_flagged(localF)

    def __push_flagged(self, flagged: list[dict[str, str]]):
        for flag in flagged:
            existing = next((item for item in self.__flagged if item["src"] == flag.get("src")), None)
            if existing and int(flag.get("occ")) >= self.__flagOccurences:
                existing["occ"] += 1
                self.__logger.warn(f"Flagged {flag.get('src')} during {existing['occ']} seconds on {existing['value']}")
            elif not existing and int(flag.get("occ")) >= self.__flagOccurences:
                self.__flagged.append({
                    "src": flag.get("src"),
                    "value": flag.get("value"),
                    "occ": 1,
                })
                self.__logger.warn(f"Flagged {flag.get('src')} for the first time on {flag.get('value')}")
            else:
                continue

    def result(self):
        return self.__flagged



