import pytest
from defusedxml.common import DefusedXmlException

from app.services.nmap_cmd import build_cmd
from app.services.nmap_parser import parse_nmap_xml

SAMPLE = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
<host><status state="up"/>
<address addr="172.30.0.11" addrtype="ipv4"/>
<address addr="02:42:AC:1E:00:0B" addrtype="mac"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.27" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="http" tunnel="ssl" conf="8"/>
<script id="vulners" output="&#xa;  cpe:/a:apache:http_server:2.4.49:&#xa;    &#x9;CVE-2021-41773&#x9;4.3&#x9;https://vulners.com/cve/CVE-2021-41773"/></port>
</ports></host>
</nmaprun>"""

EVIL = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun><host>&xxe;</host></nmaprun>"""


def test_build_cmd_is_a_list_without_shell_chars():
    cmd = build_cmd("standard", "172.30.0.0/24")
    assert isinstance(cmd, list) and cmd[0] == "nmap" and cmd[-1] == "172.30.0.0/24"


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        build_cmd("--script=evil", "172.30.0.0/24")


def test_parse_sample():
    data = parse_nmap_xml(SAMPLE)
    host = data["hosts"][0]
    assert host["ip"] == "172.30.0.11" and host["mac"] == "02:42:AC:1E:00:0B"
    assert data["nmap_version"] == "7.94"
    http, https = host["services"]
    assert http["name"] == "http" and http["product"] == "nginx" and http["confidence"] == 100
    assert https["name"] == "https"
    assert https["vulnerabilities"] == [{"cve": "CVE-2021-41773", "cvss": 4.3}]


def test_xxe_is_blocked():
    with pytest.raises(DefusedXmlException):
        parse_nmap_xml(EVIL)


def test_oversized_xml_rejected():
    with pytest.raises(ValueError):
        parse_nmap_xml("<a>" + "x" * 20_000_001 + "</a>")
