from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class PluginHealth:
    healthy: bool
    message: str


class ScannerPlugin(ABC):
    name: str
    version: str

    @abstractmethod
    def health(self) -> PluginHealth:
        raise NotImplementedError

    @abstractmethod
    def discover(self, target: str) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def scan(self, target: str) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: list[dict]) -> list[dict]:
        raise NotImplementedError
