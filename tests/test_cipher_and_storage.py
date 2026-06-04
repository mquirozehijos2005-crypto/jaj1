from pathlib import Path

from ciberbot.services import cipher_svc
from ciberbot.storage import Storage
from ciberbot.utils import crypto_box


def test_caesar_brute():
    plain = "the quick brown fox jumps over the lazy dog"
    encoded = cipher_svc.vigenere_decrypt(plain, "a")  # noop with key 'a'
    # encrypt by shifting +3 manually
    shifted = "".join(
        chr((ord(c) - 97 + 3) % 26 + 97) if "a" <= c <= "z" else c for c in plain
    )
    out = cipher_svc.caesar_brute(shifted, top=3)
    assert any("quick brown fox" in d for _, d, _ in out)
    assert encoded == plain


def test_vigenere_round_trip():
    plain = "attackatdawn"
    key = "lemon"
    cipher = "".join(
        chr((ord(p) - 97 + ord(k) - 97) % 26 + 97)
        for p, k in zip(plain, (key * 10)[: len(plain)])
    )
    assert cipher_svc.vigenere_decrypt(cipher, key) == plain


def test_xor_brute():
    data = bytes(b ^ 0x2A for b in b"Hello, world!")
    out = cipher_svc.xor_single_byte_brute(data, top=3)
    assert any("Hello, world" in d for _, d, _ in out)


def test_storage_and_crypto_box(tmp_path: Path):
    db = Storage(tmp_path / "db.sqlite")
    assert db.watch_add(1, "domain", "example.com")
    assert not db.watch_add(1, "domain", "example.com")
    assert len(db.watch_list(1)) == 1

    db.set_lang(1, "en")
    assert db.get_lang(1) == "en"

    ct, salt, nonce = crypto_box.encrypt("pw", "hola")
    assert crypto_box.decrypt("pw", ct, salt, nonce) == "hola"

    nid = db.note_save(1, "t", ct, salt, nonce)
    assert db.note_get(1, nid)["title"] == "t"
    assert db.note_delete(1, nid)
