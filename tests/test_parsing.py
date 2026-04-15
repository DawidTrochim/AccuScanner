from mininessus.parsing import parse_nmap_xml


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="web01.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
        <script id="http-title" output="Example App"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x"/></os>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_extracts_hosts_and_ports():
    hosts = parse_nmap_xml(NMAP_XML)

    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "192.168.1.10"
    assert host.hostname == "web01.local"
    assert host.status == "up"
    assert host.os_matches == ["Linux 5.x"]
    assert len(host.ports) == 2
    assert host.ports[0].port == 80
    assert host.ports[0].banner == "Example App"
    assert host.ports[1].product == "OpenSSH"
