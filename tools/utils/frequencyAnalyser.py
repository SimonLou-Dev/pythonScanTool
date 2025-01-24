
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

    def check(self, key: dict[str, str], time: int):
        if time != self.__lastSeconds:
            self.__check_occurences()
            self.__lastSeconds = time
            self.__lastSecondsOccurences = []
        self.__lastSecondsOccurences.append(key)

        return

    def __check_occurences(self):
        for key in self.__lastSecondsOccurences:
            occ: int = self.__lastSecondsOccurences.count(key)
            if occ >= self.__flagOccurences:
                self.__flagged.append(key)
                self.__logger.warn(f"Flagged {key} with {occ} more {self.__flagOccurences} per seconds")
        return
