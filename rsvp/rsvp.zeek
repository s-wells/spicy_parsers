module PacketAnalyzer::SPICY_RSVP;
module RSVP;

export {
	redef enum Log::ID += {RSVPLog};
	
	type Info: record {
		messagetype:	string &log;
		ts: 		time &log;
		id:		conn_id &log;

	done: bool &default=F;
	};

	global log_rsvp: event(rec: Info);
	
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	rsvp: Info &optional;
};

function log_pending(c: connection)
	{
	if ( ! c?$rsvp || c$rsvp$done )
		return;

	Log::write(RSVP::RSVPLog, c$rsvp);
	c$rsvp$done = T;
	}


event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88b5, "spicy::RSVP") )
		print "cannot register RSVP analyzer";
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("spicy::RSVP", 0x4950, "IP") )
		print "cannot register IP analyzer";
	
	Log::create_stream(RSVP::RSVPLog, [$columns=Info, $path="rsvp"] );
	}

function schedule_rsvp_analyzer(id: conn_id) 
	{
	# Schedule the TFTP analyzer for the expected next packet coming in on different 
        # ports. We know that it will be exchanged between same IPs and reuse the 
        # originator's port. "Spicy_RSVP" is the Zeek-side name of the RSVP analyzer 
        # (generated from "Spicy::RSVP" in rsvp.evt).
	Analyzer::schedule_analyzer(id$resp_h, id$orig_h, id$orig_p, Analyzer::get_tag("Spicy_RSVP"), 1min);
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [c$id$orig_h, c$id$resp_p, c$id$resp_h] in expected_data_conns )
		{
		c$rsvp = expected_data_conns[c$id$orig_h, c$id$resp_p, c$id$resp_h];
		#c$rsvp$uid_data = c$uid;
		add c$service["spicy_rsvp_data"];
		}
	}


event rsvp::pathmsg(c: connection)
{
	print "PATH message", c$id;
	local rec: RSVP::Info = [$messagetype = "PATH", $ts=network_time(), $id = c$id ];
	Log::write(RSVP::RSVPLog, rec);
	schedule_rsvp_analyzer(c$id);
}

event rsvp::resvmsg(c: connection)
{
	print "RESV message", c$id;
	local rec: RSVP::Info = [$messagetype = "RESV", $ts=network_time(), $id = c$id ];
	Log::write(RSVP::RSVPLog, rec);
	schedule_rsvp_analyzer(c$id);
}