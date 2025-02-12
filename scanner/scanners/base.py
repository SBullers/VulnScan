from typing import List
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScanResult:
    vulnerability_type: str
    severity: str
    description: str
    affected_component: str
    remediation: str


class ScannerAbstract(ABC):
    @abstractmethod
    async def scan(self, target: str) -> List[ScanResult]:
        pass
