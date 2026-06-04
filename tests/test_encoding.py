from ciberbot.services import encoding_svc


def test_b64_round_trip():
    assert encoding_svc.b64d(encoding_svc.b64e("hola mundo")) == "hola mundo"


def test_hex_round_trip():
    assert encoding_svc.hexd(encoding_svc.hexe("hello")) == "hello"


def test_rot_inverse():
    assert encoding_svc.rot(13, encoding_svc.rot(13, "Secret!")) == "Secret!"


def test_atbash_inverse():
    assert encoding_svc.atbash(encoding_svc.atbash("AbCdZ")) == "AbCdZ"


def test_magic_finds_b64():
    enc = encoding_svc.b64e(encoding_svc.b64e("the quick brown fox jumps over the lazy dog"))
    out = encoding_svc.magic(enc)
    assert out, "expected at least one decoding path"
    flat = " ".join(p[1] for p in out)
    assert "quick brown fox" in flat
