
from tools.utils.logger import Logger, LogLevel

class FrequencyAnalyser:
    __lastSecondsOccurences: list[dict[str, str]] = []
    __lastSeconds: int = 0
    __flagOccurences: int = 5 #Number of occurences par sec
    __flagged: list[dict[str, str]] = []
    __logger: Logger

    def __init__(self, logger: Logger, flag_occurences: int = 5):
        self.__flagOccurences = flag_occurences
        self.__logger = logger

    def check(self, key: dict[str, str, str], time: int):
        if time != self.__lastSeconds:
            self.__check_occurences()
            self.__lastSeconds = time
            self.__lastSecondsOccurences = []
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
                    "occ": 1,
                })
        self.__push_flagged(localF)

    def __push_flagged(self, flagged: list[dict[str, str]]):
        for flag in flagged:
            existing = next((item for item in self.__flagged if item["src"] == flag.get("src")), None)
            if existing and int(flag.get("occ")) >= self.__flagOccurences:
                existing["occ"] += 1
                self.__logger.warn(f"Flagged {flag.get('src')} during {existing['occ']} seconds")
            elif not existing and int(flag.get("occ")) >= self.__flagOccurences:
                self.__flagged.append({
                    "src": flag.get("src"),
                    "occ": 1,
                })
                self.__logger.warn(f"Flagged {flag.get('src')} for the first time")
            else:
                continue

    def result(self):
        return self.__flagged



