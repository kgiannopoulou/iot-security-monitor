"""IoT Security Monitor: passive network monitoring and detection for IoT/OT labs."""

__version__ = "0.1.0"

import logging as _logging

# scapy warns on import when no libpcap provider exists (normal on Windows
# without Npcap). Reading pcap files does not need one.
for _name in ("scapy.runtime", "scapy.loading"):
    _logging.getLogger(_name).setLevel(_logging.ERROR)
