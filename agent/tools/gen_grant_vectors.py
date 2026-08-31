"""Generate golden GRANT vectors from the AUDITED shared/ code, for the TS Governor port.

Run from flop-social-v1:  python agent/tools/gen_grant_vectors.py
Writes agent/vectors/grant-vectors.json.

Ed25519 signatures are deterministic (RFC 8032), so fixed seeds give stable vectors: the
TS port must reproduce grant_message byte-for-byte and verify_grant's every branch. This is
the "test the shape the caller actually sends" guard for the one thing the Governor trusts.
"""
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared import did, grant

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "grant-vectors.json")


def priv_from_seed(seed_byte):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def hexs(b):
    return b.hex()


def main():
    owner = priv_from_seed(1)
    agent = priv_from_seed(2)
    other = priv_from_seed(3)

    owner_did = did.did_from_priv(owner)
    owner_pub = did.pub_raw(owner)
    agent_did = did.did_from_priv(agent)
    other_did = did.did_from_priv(other)

    did_vectors = [
        {"seed_hex": hexs(bytes([1]) * 32), "did": owner_did, "pub_raw_hex": hexs(owner_pub)},
        {"seed_hex": hexs(bytes([2]) * 32), "did": agent_did, "pub_raw_hex": hexs(did.pub_raw(agent))},
    ]

    allow = {
        "CLAIM": 5,
        "RESULT": 5,
        "ATTEST:useful:board-match": 3,
        "ATTEST:not": 3,
        "NOTE_WRITE:note": 2,
    }

    msg_cases = [
        {"grant_id": "g1", "issued": 1000, "expiry": 2000, "window": 86400, "allow": allow},
        {"grant_id": "g2", "issued": 0, "expiry": 9999999999, "window": 3600, "allow": {}},
        {"grant_id": "g3", "issued": 5, "expiry": 10, "window": 86400,
         "allow": {"RESULT": 1}},
    ]
    message_vectors = []
    for c in msg_cases:
        msg = grant.grant_message(c["grant_id"], owner_did, agent_did, c["issued"],
                                  c["expiry"], c["window"], c["allow"])
        message_vectors.append({**c, "message_utf8": msg.decode("utf-8")})

    good = grant.build_grant(owner, "g1", agent_did, 1000, 2000, allow, window=86400)

    def case(name, g, now, revoked, expected_agent, want):
        return {"name": name, "grant": g, "now": now, "revoked": list(revoked),
                "expected_agent": expected_agent, "want": want}

    tampered_sig = dict(good)
    s = list(good["signature"])
    s[0] = "A" if s[0] != "A" else "B"
    tampered_sig["signature"] = "".join(s)

    tampered_allow = dict(good)
    tampered_allow["allow"] = {**allow, "CLAIM": 999}

    wrong_owner_did = dict(good)
    wrong_owner_did["owner_did"] = other_did

    verify_vectors = [
        case("valid", good, 1500, [], agent_did, True),
        case("valid_at_issue", good, 1000, [], agent_did, True),
        case("expired", good, 2001, [], agent_did, False),
        case("at_expiry_boundary", good, 2000, [], agent_did, True),
        case("revoked", good, 1500, ["g1"], agent_did, False),
        case("wrong_expected_agent", good, 1500, [], other_did, False),
        case("missing_expected_agent", good, 1500, [], "", False),
        case("tampered_signature", tampered_sig, 1500, [], agent_did, False),
        case("tampered_allow", tampered_allow, 1500, [], agent_did, False),
        case("wrong_owner_did", wrong_owner_did, 1500, [], agent_did, False),
    ]

    ceiling_cases = [
        {"verb": "CLAIM", "target": {"job_id": "job-x"}, "verdict": None, "board_match": False,
         "klass": "CLAIM", "ceiling": 5},
        {"verb": "RESULT", "target": {"job_id": "job-x", "result": "hi"}, "verdict": None,
         "board_match": False, "klass": "RESULT", "ceiling": 5},
        {"verb": "ATTEST", "target": {"job_id": "job-x",
         "result_hash": "a" * 64}, "verdict": {"useful": True}, "board_match": True,
         "klass": "ATTEST:useful:board-match", "ceiling": 3},
        {"verb": "ATTEST", "target": {"job_id": "job-x", "result_hash": "a" * 64},
         "verdict": {"useful": True}, "board_match": False,
         "klass": "ATTEST:useful:no-board-match", "ceiling": None},
        {"verb": "ATTEST", "target": {"job_id": "job-x", "result_hash": "a" * 64},
         "verdict": {"useful": False}, "board_match": False, "klass": "ATTEST:not", "ceiling": 3},
        {"verb": "NOTE_WRITE", "target": {"namespace": "notes", "key": "k", "value": "v"},
         "verdict": None, "board_match": False, "klass": "NOTE_WRITE:note", "ceiling": 2},
        {"verb": "NOTE_WRITE", "target": {"namespace": "did-94", "key": "k", "value": "v"},
         "verdict": None, "board_match": False, "klass": "NOTE_WRITE:identity", "ceiling": None},
        {"verb": "SAY", "target": {"room": "lobby", "text": "hi"}, "verdict": None,
         "board_match": False, "klass": "SAY", "ceiling": None},
    ]
    ceiling_vectors = []
    for c in ceiling_cases:
        klass = grant.grant_class(c["verb"], c["target"], c["verdict"], c["board_match"])
        assert klass == c["klass"], "class drift: %s != %s" % (klass, c["klass"])
        ac = grant.auto_ceiling(owner_pub, good, c["verb"], c["target"], c["verdict"],
                                c["board_match"], now=1500, revoked_ids=set(),
                                expected_agent=agent_did)
        assert ac == c["ceiling"], "ceiling drift for %s: %s != %s" % (klass, ac, c["ceiling"])
        ceiling_vectors.append(c)

    FAR = 4000000000
    governor_grants = {
        "main": grant.build_grant(owner, "g-main", agent_did, 1000, FAR,
                                  {"CLAIM": 5, "RESULT": 5, "ATTEST:not": 3, "NOTE_WRITE:note": 2,
                                   "MODEL": 2},
                                  window=86400),
        "claim1": grant.build_grant(owner, "g-claim1", agent_did, 1000, FAR,
                                    {"CLAIM": 1}, window=86400),
        "win600": grant.build_grant(owner, "g-win600", agent_did, 1000, FAR,
                                    {"CLAIM": 1}, window=600),
        "winsmall": grant.build_grant(owner, "g-winsmall", agent_did, 1000, FAR,
                                      {"CLAIM": 1}, window=100),
        "expired": grant.build_grant(owner, "g-expired", agent_did, 1000, 2000,
                                     {"CLAIM": 5}, window=86400),
        "wrong_agent": grant.build_grant(owner, "g-wrongagent", other_did, 1000, FAR,
                                         {"CLAIM": 5}, window=86400),
        "newer": grant.build_grant(owner, "g-newer", agent_did, 2000, FAR,
                                   {"CLAIM": 1}, window=86400),
        "stop": grant.build_grant(owner, "g-stop", agent_did, 3000, FAR,
                                  {}, window=86400),
        "older": grant.build_grant(owner, "g-older", agent_did, 500, FAR,
                                   {"CLAIM": 5, "MODEL": 5}, window=86400),
        "future": grant.build_grant(owner, "g-future", agent_did, 900000000000000000, FAR,
                                    {"CLAIM": 1}, window=86400),
        "prod": grant.build_grant(owner, "g-prod", agent_did, 1000, 4102444800,
                                  {"CLAIM": 1}, window=86400),
    }

    dangerous_vectors = [
        {"klass": "ATTEST:useful:no-board-match", "dangerous": True},
        {"klass": "NOTE_WRITE:identity", "dangerous": True},
        {"klass": "NOTE_WRITE:ownership", "dangerous": True},
        {"klass": "CLAIM", "dangerous": False},
        {"klass": "RESULT", "dangerous": False},
        {"klass": "ATTEST:useful:board-match", "dangerous": False},
        {"klass": "OTHER:FOO", "dangerous": True},
        {"klass": "x:unknown", "dangerous": True},
    ]
    for d in dangerous_vectors:
        assert grant.is_dangerous(d["klass"]) == d["dangerous"], d["klass"]

    out = {
        "note": "Golden GRANT vectors from the audited shared/ code. The TS Governor port must "
                "reproduce grant_message byte-for-byte and verify_grant/grant_class/auto_ceiling "
                "branch-for-branch. Regenerate with agent/tools/gen_grant_vectors.py.",
        "owner_seed_hex": hexs(bytes([1]) * 32),
        "owner_did": owner_did,
        "owner_pub_raw_hex": hexs(owner_pub),
        "agent_seed_hex": hexs(bytes([2]) * 32),
        "agent_did": agent_did,
        "other_did": other_did,
        "did_vectors": did_vectors,
        "message_vectors": message_vectors,
        "good_grant": good,
        "verify_vectors": verify_vectors,
        "ceiling_vectors": ceiling_vectors,
        "dangerous_vectors": dangerous_vectors,
        "governor_grants": governor_grants,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("wrote", os.path.normpath(OUT))
    print("owner_did", owner_did)
    print("agent_did", agent_did)
    print("message_vectors", len(message_vectors), "verify_vectors", len(verify_vectors),
          "ceiling_vectors", len(ceiling_vectors))


if __name__ == "__main__":
    main()
