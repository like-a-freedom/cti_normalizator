from typing import List, Optional
from pydantic import BaseModel


class ThreatActorNormalizedModel(BaseModel):
    canonical_name: Optional[str]
    synonyms: Optional[List[str]]
    info: Optional[str]


class MalwareNormalizedModel(BaseModel):
    canonical_name: Optional[str]
    synonyms: Optional[List[str]]
    info: Optional[str]
