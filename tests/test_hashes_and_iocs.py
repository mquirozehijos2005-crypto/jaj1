from ciberbot.services import hash_svc, ioc_svc


def test_hash_text():
    res = hash_svc.hash_text("abc")
    assert res["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert res["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hashid():
    assert "md5" in hash_svc.identify("d41d8cd98f00b204e9800998ecf8427e")
    assert "sha1" in hash_svc.identify("da39a3ee5e6b4b0d3255bfef95601890afd80709")


def test_extract_iocs():
    sample = (
        "Visit hxxps://malicious[.]example[.]com and contact attacker[@]bad.com. "
        "IP: 8.8.8.8 hash 5d41402abc4b2a76b9719d911017c592 CVE-2021-44228"
    )
    res = ioc_svc.extract(sample)
    assert "8.8.8.8" in res["ipv4"]
    assert any("malicious" in d for d in res["domains"] + res["urls"])
    assert "5d41402abc4b2a76b9719d911017c592" in res["hashes"]
    assert "CVE-2021-44228" in res["cves"]


def test_defang_refang_roundtrip():
    src = "http://example.com/path"
    assert ioc_svc.refang(ioc_svc.defang(src)) == src
