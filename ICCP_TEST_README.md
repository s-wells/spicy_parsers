# ICCP Test PCAP

This PCAP file contains a complete ICCP/TASE.2 conversation for testing the spicy-iccp analyzer.

## Contents

The PCAP contains **23 packets** with a complete ICCP session:

### TCP Connection (Packets 1-3)
- SYN: 192.168.1.10:49152 → 192.168.1.20:102
- SYN-ACK: 192.168.1.20:102 → 192.168.1.10:49152
- ACK: Complete TCP handshake

### COTP Connection Establishment (Packets 4-7)
- **COTP CR** (Connection Request): Client initiates COTP connection
  - Source Reference: 0x0001
  - Destination Reference: 0x0000
  - Class: 0x00
- **COTP CC** (Connection Confirm): Server accepts connection
  - Source Reference: 0x0000
  - Destination Reference: 0x0001

### MMS Session Initialization (Packets 8-11)
- **MMS Initiate Request**: Client requests MMS session
  - Local Detail: 1
  - Max Services Outstanding: 5 (calling) / 5 (called)
  - Nesting Level: 3
  - Version: 1
  - Services: Full service support bitmap
- **MMS Initiate Response**: Server accepts session with negotiated parameters

### MMS Identify Service (Packets 12-15)
- **MMS Identify Request**: Client requests device identification
  - Invoke ID: 1
- **MMS Identify Response**: Server provides device info
  - Vendor: "TestVendor"
  - Model: "TestModel"
  - Revision: "1.0.0"

### MMS Read Service (Packets 16-19)
- **MMS Read Request**: Client reads a variable
  - Invoke ID: 2
  - Variable: "TestVariable" (VMD-specific)
  - Specification with Result: true
- **MMS Read Response**: Server returns value
  - Value: 12345 (integer)

### MMS Write Service (Packets 20-23)
- **MMS Write Request**: Client writes a variable
  - Invoke ID: 3
  - Variable: "TestSetpoint" (VMD-specific)
  - Value: 100.5 (float)
- **MMS Write Response**: Server confirms write
  - Result: Success

## Testing the Analyzer

### Basic Test
```bash
zeek -Cr iccp_test.pcap spicy-iccp
cat iccp.log
```

### Expected Output

You should see entries in `iccp.log` for:
- COTP_CC (Connection Confirm)
- MMS_INITIATE_RESP (with negotiated parameters)
- MMS_IDENTIFY_RESP (with vendor/model/revision)
- MMS_READ_RESP (with data value)
- MMS_WRITE_RESP (write confirmation)

### Sample Log Entry
```
1736957376.001000  <uid>  192.168.1.10  49152  192.168.1.20  102  T  COTP_CC  -  1  5  5  3  1  -  -  -  -  -  1  0  0  0  0  0  0
```

### Verify Protocol Detection
```bash
zeek -Cr iccp_test.pcap -e 'event iccp_packet(c: connection, is_orig: bool, version: count, length: count) { print "ICCP detected!"; }'
```

### Debug Mode
```bash
zeek -Cr iccp_test.pcap spicy-iccp Spicy::enable_print=T
```

## Packet Details

### TPKT Structure
Each ICCP packet starts with a TPKT header:
```
Byte 0: Version (0x03)
Byte 1: Reserved (0x00)
Bytes 2-3: Length (includes TPKT header + COTP + MMS)
```

### COTP Structure
After TPKT, the COTP header:
```
Byte 0: Length Indicator
Byte 1: PDU Type (0xE0=CR, 0xD0=CC, 0xF0=DT)
Bytes 2+: PDU-specific fields
```

### MMS Structure
MMS uses ASN.1 BER encoding:
```
Tag: Identifies PDU type
  0xA8 = Initiate-Request
  0xA9 = Initiate-Response
  0xA0 = Confirmed-Request
  0xA1 = Confirmed-Response
Length: Variable length encoding
Value: PDU-specific content
```

## Protocol Flow

```
Client (192.168.1.10:49152)          Server (192.168.1.20:102)
        |                                    |
        |--- TCP SYN ----------------------->|
        |<-- TCP SYN-ACK --------------------|
        |--- TCP ACK ----------------------->|
        |                                    |
        |--- COTP CR ------------------------>|
        |<-- COTP CC -------------------------|
        |                                    |
        |--- MMS Initiate Request ---------->|
        |<-- MMS Initiate Response ----------|
        |                                    |
        |--- MMS Identify Request ---------->|
        |<-- MMS Identify Response ----------|
        |                                    |
        |--- MMS Read Request -------------->|
        |<-- MMS Read Response --------------|
        |                                    |
        |--- MMS Write Request ------------->|
        |<-- MMS Write Response -------------|
```

## Troubleshooting

### No Events Triggered
- Ensure analyzer is loaded: `zeek -NN | grep Spicy_ICCP`
- Check port 102 is registered
- Verify PCAP has TCP port 102 traffic

### Parser Errors
Enable debug output:
```bash
zeek -Cr iccp_test.pcap spicy-iccp Spicy::enable_print=T 2>&1 | grep -i error
```

### Missing Log Entries
Check if events are firing:
```bash
zeek -Cr iccp_test.pcap spicy-iccp -e '
event iccp_mms_initiate_response(c: connection, local_detail: count,
                                 max_serv_out_calling: count,
                                 max_serv_out_called: count,
                                 nesting_level: count, version: count,
                                 param_cbb: string, services: string) {
    print "MMS Initiate Response detected";
    print fmt("  Local Detail: %d", local_detail);
    print fmt("  Version: %d", version);
}'
```

## Generating Custom Test PCAPs

Use the `generate_iccp_pcap.py` script to create custom test files:

```python
# Modify packet contents
mms_read_req = create_mms_read_request()
# Add more operations
# Adjust timing
```

## References

- IEC 60870-6-503: ICCP/TASE.2 standard
- ISO 9506: MMS specification
- RFC 1006: TPKT specification
- ISO 8073: COTP specification
