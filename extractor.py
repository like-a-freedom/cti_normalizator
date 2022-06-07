import normalizer as norm
from typing import Dict, List, Optional, Tuple, Any


def extract_mitre_data(data: Dict) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        malware_names = {
            item.get("name"): item.get("x_mitre_aliases", [])
            for item in data["objects"]
            if item["type"] == "malware"
        }
        threat_actor_names = {
            item.get("name"): item.get("aliases", [])
            for item in data["objects"]
            if item["type"] == "intrusion-set"
        }
        return malware_names, threat_actor_names
    except Exception as e:
        raise Exception(e)


def extract_misp_cluster(data: Dict) -> Dict[str, List[str]]:
    if isinstance(data, dict):
        return {
            item.get("value"): item.get("meta", {}).get("synonyms", [])
            for item in data["values"]
        }
    else:
        raise Exception("Only `dict` type is allowed as an argument")


def extract_thales_data(data: List[Dict[str, Any]]) -> Optional[List[str]]:
    """
    Extracts threat actors from Thales CTI
    Note that it ignores internal `ATKXX` IDs
    """

    if isinstance(data, list):
        return [item.get("alias", []) for item in data]
    else:
        raise Exception("Only `list` type is allowed as an argument")


# TODO: Support multiple dicts merging
def merge_sources(
    dict1: Dict[str, List[str]],
    dict2: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    """
    Merge dicts on the same keys,
    values from dict1 appends to dict2
    """
    result = dict1 | dict2

    for key, value in result.items():
        if key in dict1 and key in dict2:
            result[key] = sorted(list(set(value + dict1[key])))
    return result


def deduplicate_key_values(data: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Removes values that
    equivalent to it's key's name
    """
    for k, v in data.items():
        for item in v:
            if item == k:
                v.remove(item)
    return data
