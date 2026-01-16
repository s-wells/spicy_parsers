#!/usr/bin/env python3
"""
Generate a test PCAP file for ICCP/TASE.2 protocol analyzer.
Creates valid TPKT/COTP/MMS packets without external dependencies.
"""

import struct
import time

# PCAP Global Header
PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1

def write_pcap_header(f):
    """Write PCAP global header."""
    f.write(struct.pack('<IHHIIII',
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,  # thiszone
        0,  # sigfigs
        PCAP_SNAPLEN,
        PCAP_LINKTYPE_ETHERNET
    ))

def write_pcap_packet(f, packet_data, timestamp=None):
    """Write a single packet to PCAP file."""
    if timestamp is None:
        timestamp = time.time()
    
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    
    # PCAP packet header
    f.write(struct.pack('<IIII',
        ts_sec,
        ts_usec,
        len(packet_data),  # captured length
        len(packet_data)   # original length
    ))
    
    # Packet data
    f.write(packet_data)

def create_ethernet_frame(src_mac, dst_mac, payload):
    """Create Ethernet II frame."""
    src = bytes.fromhex(src_mac.replace(':', ''))
    dst = bytes.fromhex(dst_mac.replace(':', ''))
    ethertype = struct.pack('>H', 0x0800)  # IPv4
    return dst + src + ethertype + payload

def create_ip_packet(src_ip, dst_ip, payload, protocol=6):
    """Create IPv4 packet."""
    version_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_length = 20 + len(payload)
    identification = 0x1234
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0  # Will calculate
    
    src = bytes([int(x) for x in src_ip.split('.')])
    dst = bytes([int(x) for x in dst_ip.split('.')])
    
    # Build header without checksum
    header = struct.pack('>BBHHHBBH',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum
    ) + src + dst
    
    # Calculate checksum
    checksum = calculate_checksum(header)
    
    # Rebuild with correct checksum
    header = struct.pack('>BBHHHBBH',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum
    ) + src + dst
    
    return header + payload

def create_tcp_packet(src_port, dst_port, seq, ack, flags, payload):
    """Create TCP packet."""
    data_offset = 5 << 4  # 5 * 4 = 20 bytes, no options
    window = 65535
    checksum = 0
    urgent = 0
    
    header = struct.pack('>HHIIBBHHH',
        src_port, dst_port, seq, ack,
        data_offset, flags, window, checksum, urgent
    )
    
    return header + payload

def calculate_checksum(data):
    """Calculate Internet checksum."""
    if len(data) % 2 == 1:
        data += b'\x00'
    
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_tpkt_header(length):
    """Create TPKT header (RFC 1006)."""
    version = 3
    reserved = 0
    return struct.pack('>BBH', version, reserved, length)

def create_cotp_cr():
    """Create COTP Connection Request."""
    length_indicator = 6
    pdu_type = 0xE0  # CR
    dst_ref = 0x0000
    src_ref = 0x0001
    class_option = 0x00
    
    return struct.pack('>BBHHB',
        length_indicator, pdu_type, dst_ref, src_ref, class_option
    )

def create_cotp_cc():
    """Create COTP Connection Confirm."""
    length_indicator = 6
    pdu_type = 0xD0  # CC
    dst_ref = 0x0001
    src_ref = 0x0000
    class_option = 0x00
    
    return struct.pack('>BBHHB',
        length_indicator, pdu_type, dst_ref, src_ref, class_option
    )

def create_cotp_dt(eot=True):
    """Create COTP Data Transfer header."""
    length_indicator = 2
    pdu_type = 0xF0  # DT
    tpdu_nr = 0x00
    if eot:
        tpdu_nr |= 0x80
    
    return struct.pack('>BBB', length_indicator, pdu_type, tpdu_nr)

def create_mms_initiate_request():
    """Create MMS Initiate Request PDU."""
    mms_data = b''
    
    # MMS Initiate Request tag and length
    mms_data += bytes([0xA8])  # Initiate-RequestPDU tag
    
    # Build inner content first to calculate length
    inner = b''
    
    # Local detail calling
    inner += bytes([0x80, 0x02])  # Tag and length
    inner += struct.pack('>H', 1)  # Value = 1
    
    # Proposed max serv out calling
    inner += bytes([0x81, 0x02])
    inner += struct.pack('>H', 5)  # Value = 5
    
    # Proposed max serv out called
    inner += bytes([0x82, 0x02])
    inner += struct.pack('>H', 5)  # Value = 5
    
    # Proposed data structure nesting level
    inner += bytes([0x88, 0x01])
    inner += bytes([3])  # Value = 3
    
    # MMS Init Request Detail
    detail = b''
    
    # Proposed version number
    detail += bytes([0x80, 0x01, 0x01])  # Tag, length, value=1
    
    # Proposed parameter CBB
    detail += bytes([0x81, 0x05])
    detail += bytes([0x05, 0xF1, 0x00, 0x00, 0x00])  # CBB bits
    
    # Service supported calling
    detail += bytes([0x82, 0x0E])
    detail += bytes([0x05, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00,
                    0x00, 0x79, 0xEF, 0x18, 0x00, 0x00])
    
    # Wrap detail in tag
    inner += bytes([0xA6, len(detail)]) + detail
    
    # Add length to main tag
    mms_data += bytes([len(inner)]) + inner
    
    return mms_data

def create_mms_initiate_response():
    """Create MMS Initiate Response PDU."""
    mms_data = b''
    
    # MMS Initiate Response tag
    mms_data += bytes([0xA9])
    
    inner = b''
    
    # Local detail called
    inner += bytes([0x80, 0x02])
    inner += struct.pack('>H', 1)
    
    # Negotiated max serv out calling
    inner += bytes([0x81, 0x02])
    inner += struct.pack('>H', 5)
    
    # Negotiated max serv out called
    inner += bytes([0x82, 0x02])
    inner += struct.pack('>H', 5)
    
    # Negotiated data structure nesting level
    inner += bytes([0x88, 0x01, 0x03])
    
    # MMS Init Response Detail
    detail = b''
    detail += bytes([0x80, 0x01, 0x01])  # Version
    detail += bytes([0x81, 0x05, 0x05, 0xF1, 0x00, 0x00, 0x00])  # CBB
    detail += bytes([0x82, 0x0E])
    detail += bytes([0x05, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00,
                    0x00, 0x79, 0xEF, 0x18, 0x00, 0x00])
    
    inner += bytes([0xA6, len(detail)]) + detail
    
    mms_data += bytes([len(inner)]) + inner
    
    return mms_data

def create_mms_identify_request():
    """Create MMS Identify Request."""
    # Confirmed Request PDU
    pdu = bytes([0xA0])  # Confirmed-RequestPDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x01])  # INTEGER, length 1, value 1
    
    # Identify service (empty)
    inner += bytes([0x82, 0x00])  # Identify tag, length 0
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def create_mms_identify_response():
    """Create MMS Identify Response."""
    # Confirmed Response PDU
    pdu = bytes([0xA1])  # Confirmed-ResponsePDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x01])  # INTEGER, length 1, value 1
    
    # Identify Response
    vendor = b"TestVendor"
    model = b"TestModel"
    revision = b"1.0.0"
    
    identify = b''
    identify += bytes([0x80, len(vendor)]) + vendor
    identify += bytes([0x81, len(model)]) + model
    identify += bytes([0x82, len(revision)]) + revision
    
    inner += bytes([0x82, len(identify)]) + identify
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def create_mms_read_request():
    """Create MMS Read Request."""
    pdu = bytes([0xA0])  # Confirmed-RequestPDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x02])  # INTEGER, value 2
    
    # Read service
    read_service = b''
    
    # Specification with result
    read_service += bytes([0x80, 0x01, 0x01])
    
    # Variable Access Specification - VMD specific
    var_name = b"TestVariable"
    var_spec = bytes([0xA0, len(var_name) + 2])
    var_spec += bytes([0x1A, len(var_name)]) + var_name
    
    read_service += var_spec
    
    inner += bytes([0xA4, len(read_service)]) + read_service
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def create_mms_read_response():
    """Create MMS Read Response."""
    pdu = bytes([0xA1])  # Confirmed-ResponsePDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x02])  # INTEGER, value 2
    
    # Read response
    read_resp = b''
    
    # Variable access spec
    read_resp += bytes([0x80, 0x01, 0x01])
    
    # List of access results
    value_data = struct.pack('>I', 12345)  # Example integer value
    access_result = bytes([0xA1, len(value_data) + 2])
    access_result += bytes([0x85, len(value_data)]) + value_data
    
    read_resp += access_result
    
    inner += bytes([0xA4, len(read_resp)]) + read_resp
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def create_mms_write_request():
    """Create MMS Write Request."""
    pdu = bytes([0xA0])  # Confirmed-RequestPDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x03])  # INTEGER, value 3
    
    # Write service
    write_service = b''
    
    # Variable Access Specification
    var_name = b"TestSetpoint"
    var_spec = bytes([0xA0, len(var_name) + 2])
    var_spec += bytes([0x1A, len(var_name)]) + var_name
    write_service += var_spec
    
    # List of data
    write_value = struct.pack('>f', 100.5)  # Float value
    list_of_data = bytes([0xA0, len(write_value) + 2])
    list_of_data += bytes([0x87, len(write_value)]) + write_value
    write_service += list_of_data
    
    inner += bytes([0xA5, len(write_service)]) + write_service
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def create_mms_write_response():
    """Create MMS Write Response."""
    pdu = bytes([0xA1])  # Confirmed-ResponsePDU
    
    inner = b''
    
    # Invoke ID
    inner += bytes([0x02, 0x01, 0x03])  # INTEGER, value 3
    
    # Write response - success
    write_resp = bytes([0xA5, 0x00])  # Empty = success
    
    inner += write_resp
    
    pdu += bytes([len(inner)]) + inner
    
    return pdu

def main():
    """Generate complete ICCP test PCAP."""
    
    output_file = '/mnt/user-data/outputs/iccp_test.pcap'
    
    src_ip = '192.168.1.10'
    dst_ip = '192.168.1.20'
    src_mac = '00:11:22:33:44:55'
    dst_mac = '00:aa:bb:cc:dd:ee'
    src_port = 49152
    dst_port = 102
    
    packets = []
    seq = 1000
    ack = 2000
    ts = time.time()
    
    # TCP SYN
    tcp = create_tcp_packet(src_port, dst_port, seq, 0, 0x02, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    seq += 1
    
    # TCP SYN-ACK
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x12, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    ack += 1
    
    # TCP ACK
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # COTP CR + MMS Initiate Request
    cotp_cr = create_cotp_cr()
    tpkt = create_tpkt_header(4 + len(cotp_cr))
    payload = tpkt + cotp_cr
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x18, payload)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    seq += len(payload)
    
    # TCP ACK for CR
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x10, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # COTP CC
    cotp_cc = create_cotp_cc()
    tpkt = create_tpkt_header(4 + len(cotp_cc))
    payload = tpkt + cotp_cc
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x18, payload)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    ack += len(payload)
    
    # TCP ACK for CC
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Initiate Request
    mms_init_req = create_mms_initiate_request()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_init_req))
    payload = tpkt + cotp_dt + mms_init_req
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x18, payload)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    seq += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x10, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Initiate Response
    mms_init_resp = create_mms_initiate_response()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_init_resp))
    payload = tpkt + cotp_dt + mms_init_resp
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x18, payload)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    ack += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Identify Request
    mms_identify_req = create_mms_identify_request()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_identify_req))
    payload = tpkt + cotp_dt + mms_identify_req
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x18, payload)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    seq += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x10, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Identify Response
    mms_identify_resp = create_mms_identify_response()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_identify_resp))
    payload = tpkt + cotp_dt + mms_identify_resp
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x18, payload)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    ack += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Read Request
    mms_read_req = create_mms_read_request()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_read_req))
    payload = tpkt + cotp_dt + mms_read_req
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x18, payload)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    seq += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x10, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Read Response
    mms_read_resp = create_mms_read_response()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_read_resp))
    payload = tpkt + cotp_dt + mms_read_resp
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x18, payload)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    ack += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Write Request
    mms_write_req = create_mms_write_request()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_write_req))
    payload = tpkt + cotp_dt + mms_write_req
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x18, payload)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    seq += len(payload)
    
    # TCP ACK
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x10, b'')
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.001
    
    # MMS Write Response
    mms_write_resp = create_mms_write_response()
    cotp_dt = create_cotp_dt()
    tpkt = create_tpkt_header(4 + len(cotp_dt) + len(mms_write_resp))
    payload = tpkt + cotp_dt + mms_write_resp
    tcp = create_tcp_packet(dst_port, src_port, ack, seq, 0x18, payload)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    eth = create_ethernet_frame(dst_mac, src_mac, ip)
    packets.append((eth, ts))
    ts += 0.01
    ack += len(payload)
    
    # Final ACK
    tcp = create_tcp_packet(src_port, dst_port, seq, ack, 0x10, b'')
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    eth = create_ethernet_frame(src_mac, dst_mac, ip)
    packets.append((eth, ts))
    
    # Write PCAP file
    with open(output_file, 'wb') as f:
        write_pcap_header(f)
        for packet, timestamp in packets:
            write_pcap_packet(f, packet, timestamp)
    
    print(f"Created ICCP test PCAP: {output_file}")
    print(f"Total packets: {len(packets)}")
    print("\nPackets include:")
    print("- TCP 3-way handshake")
    print("- COTP Connection Request/Confirm")
    print("- MMS Initiate Request/Response")
    print("- MMS Identify Request/Response")
    print("- MMS Read Request/Response")
    print("- MMS Write Request/Response")

if __name__ == '__main__':
    main()
