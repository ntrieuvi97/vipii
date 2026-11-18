import random

from vipii.core import Entity, resolve_overlaps


def naive_resolve(entities):
    chosen = []
    for e in sorted(entities, key=lambda e: (-e.score, -(e.end - e.start), e.start)):
        if all(e.end <= c.start or e.start >= c.end for c in chosen):
            chosen.append(e)
    return sorted(chosen, key=lambda e: e.start)


def test_fast_overlap_resolution_matches_naive_reference():
    rng = random.Random(42)
    for _ in range(2000):
        ents = []
        for _ in range(rng.randint(0, 25)):
            s = rng.randint(0, 60)
            e = s + rng.randint(1, 15)
            ents.append(Entity("T", s, e, "x", rng.choice([0.5, 0.6, 0.7, 0.9]), ""))
        assert resolve_overlaps(ents) == naive_resolve(ents)
