import sys
from termcolor import colored
from enum import Enum

class LogLevel(Enum):
    DEBUG = 'grey'
    INFO = 'green'
    WARN = 'yellow'
    ERROR = 'red'

    def __str__(self):
        return self.name.replace("_", " ").title()

class Logger:
    __verbose: bool = False
    def __init__(self, verbose=False):
        self.__verbose = verbose

    def set_verbose(self, verbose: bool):
        self.__verbose = verbose

    def _log(self, level: LogLevel, message: str):

        if not isinstance(level, LogLevel):  # Vérifie si level est bien une instance de LogLevel
            raise ValueError("Le niveau de log doit être une instance de LogLevel.")

        # Ne rien afficher en mode non-verbeux pour les messages DEBUG
        if level == LogLevel.DEBUG and not self.__verbose:
            return

        # Colorier le message avant de l'afficher
        print(colored(f"[{level}] {message}", level.value))


    def debug(self, message: str):
        self._log(LogLevel.DEBUG, message)

    def info(self, message: str):
        self._log(LogLevel.INFO, message)

    def warn(self, message: str):
        self._log(LogLevel.WARN, message)

    def error(self, message: str):
        self._log(LogLevel.ERROR, message)

    def input_and_log(self, prompt:str, level:LogLevel=LogLevel.INFO):
        user_input = input(prompt)
        self._log(level, user_input)
        return user_input



