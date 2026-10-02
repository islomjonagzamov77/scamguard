"""Tests for the APK inspector. The APKs are built here in code: no real malware is used.

`build_manifest` writes Android's binary XML (AXML) format and `build_apk` zips it, so we can
reproduce the tricks real banking trojans use to crash analysis tools.
"""

import io
import struct
import time
import zipfile
import zlib

import pytest

from scamguard import apk

ANDROID_NS = "http://schemas.android.com/apk/res/android"
P = "android.permission."


# ---------- tiny AXML writer (test fixture only) ----------

def _string_pool(strings, utf8=False):
    data, offsets = b"", []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            raw = s.encode("utf-8")
            data += bytes([len(s), len(raw)]) + raw + b"\0"
        else:
            data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    body = struct.pack(f"<{len(strings)}I", *offsets) + data
    return struct.pack("<HHIIIIII", 0x0001, header_size, header_size + len(body), len(strings), 0,
                       0x100 if utf8 else 0, strings_start, 0) + body


def build_manifest(package, permissions=(), components=(), utf8=False, launcher=True, chunk_size_zero=False):
    """components: list of (tag, permission_or_None, [actions], [categories])."""
    strings = ["name", "permission", "package", ANDROID_NS, "android", "manifest", "uses-permission",
               "application", "intent-filter", "action", "category", package]
    idx = {}

    def s(x):
        if x not in idx:
            if x not in strings:
                strings.append(x)
            idx[x] = strings.index(x)
        return idx[x]

    for name in ("name", "permission", "package", ANDROID_NS, "android"):
        s(name)
    body = []

    def attr(name_i, value, ns=True):
        return struct.pack("<IIIHBBI", s(ANDROID_NS) if ns else 0xFFFFFFFF, name_i, s(value), 8, 0, 3, s(value))

    def start(tag, attrs=()):
        attrs = list(attrs)
        chunk = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<IIHHHHHH", 0xFFFFFFFF, s(tag), 20, 20, len(attrs), 0, 0, 0)
        chunk += b"".join(attrs)
        body.append(struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk)

    def end(tag):
        chunk = struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, s(tag))
        body.append(struct.pack("<HHI", 0x0103, 16, 8 + len(chunk)) + chunk)

    start("manifest", [attr(s("package"), package, ns=False)])
    for perm in permissions:
        start("uses-permission", [attr(s("name"), perm)]); end("uses-permission")
    start("application")
    comps = list(components)
    if launcher:
        comps.append(("activity", None, ["android.intent.action.MAIN"], ["android.intent.category.LAUNCHER"]))
    for tag, perm, actions, cats in comps:
        attrs = [attr(s("name"), f"{package}.{tag.title()}")]
        if perm:
            attrs.append(attr(s("permission"), perm))
        start(tag, attrs)
        if actions or cats:
            start("intent-filter")
            for a in actions:
                start("action", [attr(s("name"), a)]); end("action")
            for c in cats:
                start("category", [attr(s("name"), c)]); end("category")
            end("intent-filter")
        end(tag)
    end("application")
    end("manifest")
    if chunk_size_zero:
        body.insert(1, struct.pack("<HHI", 0x0102, 16, 0))      # hostile: a chunk that claims size 0

    pool = _string_pool(strings, utf8)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 8) + struct.pack("<II", apk.ANDROID_NS_NAME, apk.ANDROID_NS_PERMISSION)
    content = pool + resmap + b"".join(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def build_apk(manifest, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("AndroidManifest.xml"), manifest, compress_type=method)
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 100)
    return buf.getvalue()


def tamper(data, *, encrypted=False, bogus_method=None):
    """Apply the anti-analysis tricks malware uses to every header of AndroidManifest.xml."""
    data = bytearray(data)
    for sig, flag_at, method_at in ((b"PK\x03\x04", 6, 8), (b"PK\x01\x02", 8, 10)):
        pos = data.find(sig)
        while pos >= 0:
            name_at = pos + (30 if sig == b"PK\x03\x04" else 46)
            if data[name_at:name_at + 19] == b"AndroidManifest.xml":
                if encrypted:
                    struct.pack_into("<H", data, pos + flag_at, struct.unpack_from("<H", data, pos + flag_at)[0] | 1)
                if bogus_method is not None:
                    struct.pack_into("<H", data, pos + method_at, bogus_method)
            pos = data.find(sig, pos + 4)
    return bytes(data)


# ---------- realistic app shapes ----------

SMS_STEALER = build_manifest(
    "uz.invitation.photo",
    permissions=[P + "RECEIVE_SMS", P + "READ_SMS", P + "INTERNET", P + "READ_PHONE_STATE"],
    components=[("receiver", None, ["android.provider.Telephony.SMS_RECEIVED"], [])],
    launcher=False,
)
OVERLAY_TROJAN = build_manifest(
    "com.bank.update.secure",
    permissions=[P + "SYSTEM_ALERT_WINDOW", P + "REQUEST_INSTALL_PACKAGES", P + "QUERY_ALL_PACKAGES", P + "INTERNET"],
    components=[("service", P + "BIND_ACCESSIBILITY_SERVICE", ["android.accessibilityservice.AccessibilityService"], [])],
)
NORMAL_APP = build_manifest("com.example.calculator", permissions=[P + "INTERNET"])


def test_sms_stealer_is_explained():
    report = apk.inspect_apk(build_apk(SMS_STEALER))
    assert report.package == "uz.invitation.photo"
    assert P + "RECEIVE_SMS" in report.permissions
    signals = apk.report_signals(report)
    assert signals[0] == "apk_reads_sms"                      # most dangerous first
    assert "apk_hidden_icon" in signals                      # no launcher icon: runs hidden
    text = " ".join(r.text("en") for r in apk.report_reasons(report))
    assert "SMS" in text and "uz.invitation.photo" in text and report.sha256[:16] in text


def test_accessibility_overlay_trojan():
    signals = apk.report_signals(apk.inspect_apk(build_apk(OVERLAY_TROJAN)))
    for expected in ("apk_accessibility", "apk_overlay", "apk_installs_apps", "apk_sees_apps"):
        assert expected in signals
    assert "apk_hidden_icon" not in signals                  # it does have an icon
    assert "apk_evasion" not in signals


def test_normal_app_still_gets_a_warning_but_no_false_capabilities():
    report = apk.inspect_apk(build_apk(NORMAL_APP))
    assert apk.report_signals(report) == []
    reasons = apk.report_reasons(report)
    assert reasons[0] is apk.NOTHING_FOUND                   # never "this app is safe"


def test_utf8_string_pool_and_stored_entries():
    m = build_manifest("uz.test.utf8", permissions=[P + "READ_SMS"], utf8=True)
    report = apk.inspect_apk(build_apk(m, method=zipfile.ZIP_STORED))
    assert report.package == "uz.test.utf8" and P + "READ_SMS" in report.permissions


@pytest.mark.parametrize("trick", [dict(encrypted=True), dict(bogus_method=0x1F2E), dict(encrypted=True, bogus_method=99)])
def test_reads_through_anti_analysis_tricks(trick):
    tampered = tamper(build_apk(SMS_STEALER, method=zipfile.ZIP_STORED), **trick)
    with pytest.raises(Exception):                           # the standard library gives up...
        zipfile.ZipFile(io.BytesIO(tampered)).read("AndroidManifest.xml")
    report = apk.inspect_apk(tampered)                       # ...ScamGuard doesn't
    signals = apk.report_signals(report)
    assert "apk_reads_sms" in signals and "apk_evasion" in signals


def test_bogus_method_on_deflated_entry():
    report = apk.inspect_apk(tamper(build_apk(SMS_STEALER), bogus_method=0x4242))
    assert "apk_reads_sms" in apk.report_signals(report)


def test_damaged_central_directory_falls_back_to_local_headers():
    data = build_apk(SMS_STEALER)
    broken = data[: data.find(b"PK\x01\x02")]                # cut off the whole directory
    report = apk.inspect_apk(broken)
    assert "apk_reads_sms" in apk.report_signals(report)
    assert "damaged zip directory" in report.tolerated


@pytest.mark.parametrize("data", [
    b"",
    b"\x89PNG\r\n\x1a\n" + b"\0" * 500,
    b"PK\x03\x04" + b"\xff" * 200,
])
def test_not_an_apk(data):
    with pytest.raises(apk.NotAnApk):
        apk.inspect_apk(data)


def test_zip_without_manifest_is_not_an_apk():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("photo.jpg", b"\xff\xd8\xff" + b"\0" * 100)
    with pytest.raises(apk.NotAnApk):
        apk.inspect_apk(buf.getvalue())


def raw_zip(name: bytes, payload: bytes, method: int, usize: int, crc: int = 0) -> bytes:
    """One-entry zip written by hand, so sizes and methods can say anything we want."""
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, method, 0, 0, crc, len(payload), usize, len(name), 0)
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, method, 0, 0, crc, len(payload), usize,
                          len(name), 0, 0, 0, 0, 0, 0)
    cd_offset = len(local) + len(name) + len(payload)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central) + len(name), cd_offset, 0)
    return local + name + payload + central + name + eocd


def test_raw_zip_helper_matches_python():
    m = build_manifest("uz.helper", permissions=[P + "READ_SMS"])
    data = raw_zip(b"AndroidManifest.xml", m, 0, len(m), zlib.crc32(m))
    assert zipfile.ZipFile(io.BytesIO(data)).read("AndroidManifest.xml") == m
    assert P + "READ_SMS" in apk.inspect_apk(data).permissions


def test_zip_bomb_manifest_is_refused_quickly():
    z = zlib.compressobj(9, zlib.DEFLATED, -15)
    bomb = z.compress(b"\0" * (60 * 1024 * 1024)) + z.flush()          # 60 MB of zeros in ~60 KB
    t0 = time.time()
    with pytest.raises(apk.NotAnApk):
        apk.inspect_apk(raw_zip(b"AndroidManifest.xml", bomb, 8, 60 * 1024 * 1024))
    assert time.time() - t0 < 2


def test_hostile_chunk_size_does_not_hang():
    m = build_manifest("uz.hostile", permissions=[P + "READ_SMS"], chunk_size_zero=True)
    t0 = time.time()
    try:
        apk.inspect_apk(build_apk(m))
    except apk.NotAnApk:
        pass
    assert time.time() - t0 < 2


def test_too_large_file_is_refused():
    with pytest.raises(apk.NotAnApk):
        apk.inspect_apk(b"PK" + b"\0" * (apk.MAX_APK_BYTES + 1))
