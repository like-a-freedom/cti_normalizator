import json
import pathlib
from unittest import result

from sklearn.utils import resample
import normalizer as norm
from os.path import join


MOCKS_DIR = join(pathlib.Path(__file__).parent.absolute(), "fixtures")


def load_json(path: str):
    with open(path, "r") as file:
        return json.load(file)


class TestExtractor:
    def test_is_canonical_malware_name(self):
        result = norm._is_canonical_malware_name("3PARA RAT")
        assert result == True
        result = norm._is_canonical_malware_name("CobaltStrike")
        assert result == False
        result = norm._is_canonical_malware_name("AZZY")
        assert result == False
        result = norm._is_canonical_malware_name(" ")
        assert result == False

    def test_is_canonical_threat_actor_name(self):
        result = norm._is_canonical_threat_actor_name("Fox Kitten")
        assert result == True
        result = norm._is_canonical_threat_actor_name("Parisite")
        assert result == False
        result = norm._is_canonical_threat_actor_name(" ")
        assert result == False

    def test_get_malware_synonyms(self):
        result = norm._get_malware_synonyms("TerraStealer")
        assert result == ["SONE", "StealerOne", "Taurus Loader Stealer Module"]
        result = norm._get_malware_synonyms(" ")
        assert result == []

    def test_get_threat_actor_synonyms(self):
        result = norm._get_threat_actor_synonyms("APT1")
        assert result == ["Comment Crew", "Comment Group", "Comment Panda"]
        result = norm._get_threat_actor_synonyms(" ")
        assert result == []

    def test_normalize_threat_actor_name(self):
        result = norm.normalize_threat_actor_name("NOBELIUM", return_synonyms=True)
        assert result == {
            "canonical_name": "UNC2452",
            "synonyms": ["Dark Halo", "DarkHalo", "NOBELIUM", "StellarParticle"],
        }

    def test_normalize_malware_name(self):
        result = norm.normalize_malware_name("Totbrick", return_synonyms=True)
        assert result == {
            "canonical_name": "TrickBot",
            "synonyms": [
                "TSPY_TRICKLOAD",
                "TheTrick",
                "Totbrick",
                "TrickLoader",
                "Trickster",
            ],
        }
