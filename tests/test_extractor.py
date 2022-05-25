import json
import pathlib
import extractor
from os.path import join


MOCKS_DIR = join(pathlib.Path(__file__).parent.absolute(), "fixtures")


def load_json(path: str):
    with open(path, "r") as file:
        return json.load(file)


class TestExtractor:
    def test_extract_mitre_data(self):
        data = load_json(join(MOCKS_DIR, "raw/mitre/mitre_data.json"))
        result = extractor.extract_mitre_data(data)
        assert isinstance(result, (tuple))
        assert result[0]["ADVSTORESHELL"] == [
            "ADVSTORESHELL",
            "AZZY",
            "EVILTOSS",
            "NETUI",
            "Sedreco",
        ]
        assert result[1]["menuPass"] == [
            "menuPass",
            "Cicada",
            "POTASSIUM",
            "Stone Panda",
            "APT10",
            "Red Apollo",
            "CVNX",
            "HOGFISH",
        ]

    def test_extract_misp_clusters(self):
        data = load_json(join(MOCKS_DIR, "raw/misp/misp_malpedia.json"))
        result = extractor.extract_misp_cluster(data)
        assert isinstance(result, (dict))
        assert result["Pkybot"] == ["Bublik", "Pykbot", "TBag"]
        assert result["PLEAD (Windows)"] == ["DRAWDOWN", "GOODTIMES", "Linopid"]

    def test_merge_sources(self):
        dict1 = {
            "key_01": ["value_01", "value_02", "value_03"],
            "key_02": ["value_10", "value_11"],
            "key_03": ["value_01"],
        }
        dict2 = {
            "key_01": ["value_01"],
            "key_02": ["value_02", "value_10", "value_20"],
            "key_04": ["value_04"],
        }
        result = extractor.merge_sources(dict1, dict2)
        assert result == {
            "key_01": ["value_01", "value_02", "value_03"],
            "key_02": ["value_02", "value_10", "value_11", "value_20"],
            "key_03": ["value_01"],
            "key_04": ["value_04"],
        }

    def test_deduplicate_key_values(self):
        duplicated = {
            "key_01": ["key_01", "value_02", "value_03"],
            "key_02": ["value_10", "value_11"],
            "key_03": ["key_03"],
        }
        result = extractor.deduplicate_key_values(duplicated)
        assert result == {
            "key_01": ["value_02", "value_03"],
            "key_02": ["value_10", "value_11"],
            "key_03": [],
        }
