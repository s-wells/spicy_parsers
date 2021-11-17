module PacketAnalyzer::SPICY_OSPF;
module OSPF;

redef ignore_checksums = T;
redef Spicy::enable_print=T;


export {

    const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;

    redef enum Log::ID += {WGLOG};

    type Info: record {
      OSPFLog:		string &log &optional;
      id: 		conn_id &log;

    };

}


event zeek_init()
    {
    #if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x0800, "spicy::OSPF") )
    #        Reporter::error("cannot register OSPF analyzer");

    #if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("spicy::OSPF", 0x0800, "IP") )
	#	print "cannot register IP analyzer";

    Log::create_stream(OSPF::WGLOG, [$columns=Info, $path="ospf"] );

    }

function schedule_ospf_analyzer(id: conn_id) 
	{
	# Schedule the TFTP analyzer for the expected next packet coming in on different 
        # ports. We know that it will be exchanged between same IPs and reuse the 
        # originator's port. "Spicy_OSPF" is the Zeek-side name of the TFTP analyzer 
        # (generated from "Spicy::OSPF" in tftp.evt).
	Analyzer::schedule_analyzer(id$resp_h, id$orig_h, id$orig_p, Analyzer::get_tag("Spicy_OSPF"), 1min);

	}

event OSPF::hello_packet(c: connection, netmask: addr, desig_router: addr)
	{
	print "Hello Packet", c$id, netmask, desig_router;
	local rec: OSPF::Info = [ $OSPFLog = "This is a Hello Packet", $id = c$id ];
	Log::write(OSPF::WGLOG, rec);
	schedule_ospf_analyzer(c$id);
	}

event OSPF::database(c: connection)
	{
	print "Database Packet", c$id;
	local rec: OSPF::Info = [ $OSPFLog = "This is a Database Packet", $id = c$id ];
	Log::write(OSPF::WGLOG, rec);

	schedule_ospf_analyzer(c$id);
	}

event ospf::link_request(c: connection)
	{
	print "Link Request", c$id;
	local rec: OSPF::Info = [ $OSPFLog = "This is a Link Request Packet", $id = c$id ];
	Log::write(OSPF::WGLOG, rec);
	schedule_ospf_analyzer(c$id);
	}

event ospf::link_update(c: connection)
	{
	print "Link Update", c$id;
	local rec: OSPF::Info = [ $OSPFLog = "This is a Link Update Packet", $id = c$id ];
	Log::write(OSPF::WGLOG, rec);
	schedule_ospf_analyzer(c$id);
	}

event ospf::link_ack(c: connection)
	{
	print "Link Ack", c$id;
	local rec: OSPF::Info = [ $OSPFLog = "This is a Link Ack Packet", $id = c$id ];
	Log::write(OSPF::WGLOG, rec);
	schedule_ospf_analyzer(c$id);
	}