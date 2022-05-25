# What's that?

The idea is to create a simple package that is inteded for threat intelligence threat actors and malwares normalization: there are a lot of threat actors and malwares that has more than one name and sometimes you need to quickly answer the question "Does the malware/threat actor have a main (canonical)" name? The package provide realy simple algorithm that is based on the couple of steps — strict matching and fuzzy matching.

## Idea

Main idea is so simple:

* Check origin name if it is a canonical name (strict match)
  * If yes, then return canonical name.
  * If no, check if origin name is similar to canonical name (fuzzy match).
    * If yes, then return canonical name of this synonym.
    * If no, check if origin name is similar to synonyms (fuzzy match).
* In case if there are no mathes on the previous steps, then return origin name — so that we can't normalize this name now ¯\_(ツ)_/¯

## How can you use it?

As a package:

```python
import normalizer as norm

result = norm.normalize_threat_actor_name("NOBELIUM")
...
{
    "canonical_name": "UNC2452",
    "synonyms": ["Dark Halo", "DarkHalo", "NOBELIUM", "StellarParticle"],
}

result = norm.normalize_malware_name("Totbrick")
...
{
    "canonical_name": "TrickBot",
    "synonyms": [
        "TSPY_TRICKLOAD",
        "TheTrick",
        "Totbrick",
        "TrickLoader",
        "Trickster",
    ],
}
```

Also, have a look at the tests — that's the simple explanation how does it work.
