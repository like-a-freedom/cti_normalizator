import os
import ujson as json
import httpx
import extractor
from typing import Any


client = httpx.Client(timeout=60)

DATA_PATH = "./data"
MALWARES_PATH = os.path.join(DATA_PATH, "malwares.json")
THREAT_ACTORS_PATH = os.path.join(DATA_PATH, "threat_actors.json")

MITRE_REPO_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MISP_THREAT_ACTOR_URL: str = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)
MISP_MALPEDIA_URL: str = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"
)
MISP_BANKERS_URL: str = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/banker.json"
)
THALES_CTI_URL: str = "https://cyberthreat.thalesgroup.com/api/adversaries"


def __get_data(url: str) -> Any:
    try:
        with httpx.Client() as client:
            response = client.get(url)
            response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        raise Exception(e)


def update_sources() -> None:
    try:
        mitre_malware_names, mitre_threat_actor_names = extractor.extract_mitre_data(
            __get_data(MITRE_REPO_URL)
        )
        misp_threat_actor_names = extractor.extract_misp_cluster(
            __get_data(MISP_THREAT_ACTOR_URL)
        )
        malpedia_malwares = extractor.extract_misp_cluster(
            __get_data(MISP_MALPEDIA_URL)
        )

        # TODO: Add this sources ?
        # misp_bankers_malware = extractor.extract_misp_cluster(
        #     __get_data(MISP_BANKERS_URL)
        # )
        #
        # thales_threat_actors = extractor.extract_thales_data(__get_data(THALES_CTI_URL))

        malwares = extractor.deduplicate_key_values(
            extractor.merge_sources(mitre_malware_names, malpedia_malwares)
        )
        threat_actors = extractor.deduplicate_key_values(
            extractor.merge_sources(mitre_threat_actor_names, misp_threat_actor_names)
        )

        with open(MALWARES_PATH, "w") as file:
            json.dump(malwares, file)
        with open(THREAT_ACTORS_PATH, "w") as file:
            json.dump(threat_actors, file)

    except Exception as e:
        raise Exception(e)
