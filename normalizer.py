import json
from typing import Dict, List, Optional, Union
import jellyfish as jf
import os

from downloader import DATA_PATH

DATA_PATH = "./data"

MALWARES_PATH = os.path.join(DATA_PATH, "malwares.json")
THREAT_ACTORS_PATH = os.path.join(DATA_PATH, "threat_actors.json")

THREAT_ACTOR_SIMILARITY_RATIO: float = 0.7
MALWARE_SIMILARITY_RATIO: float = 0.8


def load_malware_db() -> Dict[str, List[str]]:
    with open(MALWARES_PATH, "r") as file:
        return json.load(file)


def load_threat_actor_db() -> Dict[str, List[str]]:
    with open(THREAT_ACTORS_PATH, "r") as file:
        return json.load(file)


malwares = load_malware_db()
threat_actors = load_threat_actor_db()


def _is_canonical_malware_name(malware_name: str) -> bool:
    return malware_name in malwares.keys()


def _is_canonical_threat_actor_name(threat_actor_name: str) -> bool:
    return threat_actor_name in threat_actors.keys()


def _get_malware_synonyms(malware_name: str) -> List[str]:
    try:
        return malwares[malware_name]
    except:
        return []


def _get_threat_actor_synonyms(threat_actor_name: str) -> List[str]:
    try:
        return threat_actors[threat_actor_name]
    except:
        return []


def _get_most_similar_threat_actor_cname(threat_actor_name: str) -> Optional[str]:
    """
    Returns most similar canonical
    threat actor name if exists,
    else returns `None`
    """
    for canonical_name in threat_actors.keys():
        similarity = jf.jaro_winkler_similarity(canonical_name, threat_actor_name)
        if similarity > THREAT_ACTOR_SIMILARITY_RATIO:
            return canonical_name
        return None


def _get_most_similar_threat_actor_synonym(
    threat_actor_name: str,
) -> Optional[str]:
    for cname, synonyms in threat_actors.items():
        for synonym in synonyms:
            similarity = jf.jaro_winkler_similarity(synonym, threat_actor_name)
            if similarity > THREAT_ACTOR_SIMILARITY_RATIO:
                return cname
    return None


def _get_most_similar_malware_cname(malware_name: str) -> Optional[str]:
    """
    Returns most similar canonical
    malware name if exists,
    else returns `None`
    """
    for canonical_name in malwares.keys():
        similarity = jf.jaro_winkler_similarity(canonical_name, malware_name)
        if similarity > MALWARE_SIMILARITY_RATIO:
            return canonical_name
        return None


def _get_most_similar_malware_synonym(malware_name: str) -> Optional[str]:
    for cname, synonyms in malwares.items():
        for synonym in synonyms:
            similarity = jf.jaro_winkler_similarity(synonym, malware_name)
            if similarity > MALWARE_SIMILARITY_RATIO:
                return cname
    return None


def normalize_threat_actor_name(
    threat_actor_name: str, return_synonyms: bool = False
) -> Optional[Union[str, Dict]]:
    if _is_canonical_threat_actor_name(threat_actor_name):
        if return_synonyms:
            return {
                "canonical_name": threat_actor_name,
                "synonyms": _get_threat_actor_synonyms(threat_actor_name),
            }
        else:
            return threat_actor_name
    else:
        cname_match = _get_most_similar_threat_actor_cname(threat_actor_name)
        if cname_match:
            if return_synonyms:
                return {
                    "canonical_name": cname_match,
                    "synonyms": _get_threat_actor_synonyms(cname_match),
                }
            else:
                return cname_match
        else:
            synonym_match = _get_most_similar_threat_actor_synonym(threat_actor_name)
            if synonym_match:
                if return_synonyms:
                    return {
                        "canonical_name": synonym_match,
                        "synonyms": _get_threat_actor_synonyms(synonym_match),
                    }
                else:
                    return synonym_match
            else:
                return threat_actor_name


def normalize_malware_name(
    malware_name: str, return_synonyms=False
) -> Optional[Union[str, Dict]]:
    if _is_canonical_malware_name(malware_name):
        if return_synonyms:
            return {
                "canonical_name": malware_name,
                "synonyms": _get_malware_synonyms(malware_name),
            }
        else:
            return malware_name
    else:
        cname_match = _get_most_similar_malware_cname(malware_name)
        if cname_match:
            if return_synonyms:
                return {
                    "canonical_name": cname_match,
                    "synonyms": _get_malware_synonyms(cname_match),
                }
            else:
                return cname_match
        else:
            synonym_match = _get_most_similar_malware_synonym(malware_name)
            if synonym_match:
                if return_synonyms:
                    return {
                        "canonical_name": synonym_match,
                        "synonyms": _get_malware_synonyms(synonym_match),
                    }
                else:
                    return synonym_match
            else:
                return malware_name
