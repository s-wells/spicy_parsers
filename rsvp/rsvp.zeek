module RSVP;

export {
	redef enum Log::ID += { RSVP_Log };
	
	type Info: record {
		ts: 		time &log &default=network_time();
		ip_src: addr &log &optional;
		ip_dst: addr &log &optional;
		version: count &log &optional;
		rsvp_type:	string &log &optional;
		objclass: vector of string &log &optional;
		hop_neighbor: addr &log &optional;
		route_addr: addr &log &optional;
		attribute_name: string &log &optional;
		sendertemp_addr: addr &log &optional;
		conf_receiver_addr: addr &log &optional;
		filter_sender_addr: addr &log &optional;

	done: bool &default=F;
	};

	global RSVP::message: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType);
	global RSVP::objecttypes: event(pkt: raw_pkt_hdr, obj_type: zeek_spicy_rsvp::ObjClass);
	global RSVP::resvhop: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, hop_neighbor: addr);
	global RSVP::explicitrt: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, route_addr: addr);
	global RSVP::sessattr: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, attribute_name: string);
	global RSVP::sendertemp: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, sendertemp_addr: addr);
	global RSVP::resvconf: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, conf_receiver_addr: addr);
	global RSVP::filterspec: event(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, filter_sender_addr: addr);
	
	global RSVP::log_rsvp: event(rec: RSVP::Info);
	
#	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

redef record raw_pkt_hdr += {
	rsvp: Info &optional;
};

function set_session(p: raw_pkt_hdr)
    {
    if ( ! p?$rsvp)
        {
        p$rsvp = [];
        p$rsvp$objclass = vector();
        #p$rsvp$link_prefixes = set();
        #p$rsvp$metrics = vector();
        #p$rsvp$fwd_addrs = vector();
        #p$rsvp$route_tags = vector();
        }
    }

const MsgTypes = {
    [zeek_spicy_rsvp::MsgType_Resv] = "RESV",
    [zeek_spicy_rsvp::MsgType_Path] = "PATH",
    [zeek_spicy_rsvp::MsgType_ResvConf] = "RESV Confirm",
    [zeek_spicy_rsvp::MsgType_PathErr] = "PATH Error",
    [zeek_spicy_rsvp::MsgType_ResvErr] = "RESV Error",
	[zeek_spicy_rsvp::MsgType_PathTear] = "PATH Tear",
    [zeek_spicy_rsvp::MsgType_ResvTear] = "RESV Tear",
	[zeek_spicy_rsvp::MsgType_Dreq] = "DREQ",
	[zeek_spicy_rsvp::MsgType_Drep] = "DREP",
	[zeek_spicy_rsvp::MsgType_ResvTearCon] = "RESV Tear Confirm",
	[zeek_spicy_rsvp::MsgType_Bundle] = "Bundle",
	[zeek_spicy_rsvp::MsgType_Ack] = "Ack",
	[zeek_spicy_rsvp::MsgType_Srefresh] = "Srefresh",
	[zeek_spicy_rsvp::MsgType_Hello] = "Hello",
	[zeek_spicy_rsvp::MsgType_Notify] = "Notify",
	[zeek_spicy_rsvp::MsgType_IntgChal] = "Integrity Challenge",
	[zeek_spicy_rsvp::MsgType_IntgResp] = "Integrity Response",
	[zeek_spicy_rsvp::MsgType_RecPath] = "Recovery Path",
  } &default = "FIXME-Unknown";

const ObjClass = {
	[zeek_spicy_rsvp::ObjClass_Session] = "Session",
	[zeek_spicy_rsvp::ObjClass_Rsvp_Hop] = "RSVP Hop",
	[zeek_spicy_rsvp::ObjClass_Integrity]= "Integrity",
	[zeek_spicy_rsvp::ObjClass_Time_Values]= "Time Values",
	[zeek_spicy_rsvp::ObjClass_Error_Spec]= "Error Spec",
	[zeek_spicy_rsvp::ObjClass_Scope] = "Scope",
	[zeek_spicy_rsvp::ObjClass_Style]= "Style",
	[zeek_spicy_rsvp::ObjClass_Flowspec]= "Flow Spec",
	[zeek_spicy_rsvp::ObjClass_Filter_Spec]= "Filter Spec",
	[zeek_spicy_rsvp::ObjClass_Sender_Temp]= "Sender Temp",
	[zeek_spicy_rsvp::ObjClass_Sender_Tspec]= "Sender Tpec",
	[zeek_spicy_rsvp::ObjClass_Adspec] = "Adspec",
	[zeek_spicy_rsvp::ObjClass_Policy_Data]= "Policy Data",
	[zeek_spicy_rsvp::ObjClass_Resv_Conf]= "Resv Confirm",
	[zeek_spicy_rsvp::ObjClass_Rsvp_Label]= "RSVP Label",
	[zeek_spicy_rsvp::ObjClass_Hop_Count]= "Hop Count",
	[zeek_spicy_rsvp::ObjClass_Strict_Source] = "Strict Source",
	[zeek_spicy_rsvp::ObjClass_Label_Req] = "Label Request",
	[zeek_spicy_rsvp::ObjClass_Explicit_Rt] = "Explicit Route",
	[zeek_spicy_rsvp::ObjClass_Route_Rec] = "Route Rec",
	[zeek_spicy_rsvp::ObjClass_Hello] = "Hello",
	[zeek_spicy_rsvp::ObjClass_Message_Id] = "Message ID",
	[zeek_spicy_rsvp::ObjClass_Mess_Id_Ack] = "Message ID Ack",
	[zeek_spicy_rsvp::ObjClass_Mess_Id_List] = "Message ID List",
	[zeek_spicy_rsvp::ObjClass_Diagnostic]= "Diagnostic",
	[zeek_spicy_rsvp::ObjClass_Route_class]= "Route Class",
	[zeek_spicy_rsvp::ObjClass_Diag_Resp] = "Diag Resp",
	[zeek_spicy_rsvp::ObjClass_Diag_Slct] = "Diag Slct",
	[zeek_spicy_rsvp::ObjClass_Rec_Label]= "Rec Label",
	[zeek_spicy_rsvp::ObjClass_Up_Label] = "Up Label",
	[zeek_spicy_rsvp::ObjClass_Label_Set]= "Label Set",
	[zeek_spicy_rsvp::ObjClass_Protection] = "Protection",
	[zeek_spicy_rsvp::ObjClass_Prim_Path] = "Prim Path",
	[zeek_spicy_rsvp::ObjClass_DSBM_IP] = "DSBM IP",
	[zeek_spicy_rsvp::ObjClass_SMB_Priority] = "SMB Priority",
	[zeek_spicy_rsvp::ObjClass_DSMB_Timer] = "DSMB Timer",
	[zeek_spicy_rsvp::ObjClass_SMB_Info]= "SMB Info",
	[zeek_spicy_rsvp::ObjClass_S2L_Sub] = "S2L Sub",
	[zeek_spicy_rsvp::ObjClass_Detour] = "Detour",
	[zeek_spicy_rsvp::ObjClass_Challenge] = "Challenge",
	[zeek_spicy_rsvp::ObjClass_Diff_Serv] = "Diff Serv",
	[zeek_spicy_rsvp::ObjClass_Class_Type] = "Class Type",
	[zeek_spicy_rsvp::ObjClass_LSP_Req] = "LSP Req",
	[zeek_spicy_rsvp::ObjClass_Up_Flowspec] = "Up Flowspec",
	[zeek_spicy_rsvp::ObjClass_Up_Tspec] = "Up Tspec",
	[zeek_spicy_rsvp::ObjClass_Up_Adspec] = "Up Adspec",
	[zeek_spicy_rsvp::ObjClass_Node_Char] = "Node Char",
	[zeek_spicy_rsvp::ObjClass_Sugg_Label]= "Sugg Label",
	[zeek_spicy_rsvp::ObjClass_Accept_Label] = "Accept Label",
	[zeek_spicy_rsvp::ObjClass_Restart_Cap] = "Restart Cap",
	[zeek_spicy_rsvp::ObjClass_Sess_Interest] = "Session Interest",
	[zeek_spicy_rsvp::ObjClass_Link_Cap] = "Link Cap",
	[zeek_spicy_rsvp::ObjClass_Cap_Obj] = "Cap Obj",
	[zeek_spicy_rsvp::ObjClass_Rsvp_Hop_L2] = "RSVP Hop L2",
	[zeek_spicy_rsvp::ObjClass_LAN_NHOP_L2] = "LAN NHOP L2",
	[zeek_spicy_rsvp::ObjClass_LAN_NHOP_L3] = "LAN NHOP L3",
	[zeek_spicy_rsvp::ObjClass_LAN_Loopback] = "LAN Loopback",
	[zeek_spicy_rsvp::ObjClass_Tclass] = "Tclass",
	[zeek_spicy_rsvp::ObjClass_Session_Assoc] = "Session Association",
	[zeek_spicy_rsvp::ObjClass_LSP_Tunnel_ID] = "LSP Tunnel ID",
	[zeek_spicy_rsvp::ObjClass_User_Error_Spec] = "User Error Spec",
	[zeek_spicy_rsvp::ObjClass_Notify_Req] = "Notify Req",
	[zeek_spicy_rsvp::ObjClass_Admin_Status] = "Admin Status",
	[zeek_spicy_rsvp::ObjClass_LSP_Attr] = "LSP Attribute",
	[zeek_spicy_rsvp::ObjClass_Alarm_Spec] = "Alarm Spec",
	[zeek_spicy_rsvp::ObjClass_Assoc] = "Association",
	[zeek_spicy_rsvp::ObjClass_Sec_Expl_Rte] = "Secondary Explicit Route",
	[zeek_spicy_rsvp::ObjClass_Sec_Rec_Rte] = "Secondary Rec Route",
	[zeek_spicy_rsvp::ObjClass_Call_Attributes] = "Call Attributes",
	[zeek_spicy_rsvp::ObjClass_Reverse_LSP] = "Reverse LSP",
	[zeek_spicy_rsvp::ObjClass_S2L_Sub_LSP] = "S2L Sub LSP",
	[zeek_spicy_rsvp::ObjClass_Fast_ReRte] = "Fast ReRoute",
	[zeek_spicy_rsvp::ObjClass_Sess_Attr] = "Session Attribute",
	[zeek_spicy_rsvp::ObjClass_DClass] = "DClass",
	[zeek_spicy_rsvp::ObjClass_PktCable_Ext] = "Packet Cable Extention",
	[zeek_spicy_rsvp::ObjClass_ATM_Serv_Class] = "ATM Service Class",
	[zeek_spicy_rsvp::ObjClass_Call_Ops] = "Call Ops",
	[zeek_spicy_rsvp::ObjClass_Gen_Uni] = "Gen Uni",
	[zeek_spicy_rsvp::ObjClass_Call_ID] = "Call ID",
	[zeek_spicy_rsvp::ObjClass_GPP2_Obj] = "GPP2 Object", 
	[zeek_spicy_rsvp::ObjClass_PCN] = "PCN"
  } &default = "FIXME-Unknown";



event zeek_init()
    {
    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x2E, "spicy::RSVP") )
		Reporter::error("cannot register RSVP Spicy analyzer");
    }

event RSVP::message(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst];
	Log::write(RSVP::RSVP_Log, rec);
	#print fmt("Packet received.");
}

event RSVP::objecttypes(pkt: raw_pkt_hdr, obj_types: zeek_spicy_rsvp::ObjClass)
{
	set_session(pkt);
	local rec: RSVP::Info = [$ts=network_time(), $ip_src=pkt$ip$src, $ip_dst=pkt$ip$dst, $objclass=vector(ObjClass[obj_types])];
	#Log::write(RSVP::RSVP_Log, rec);
}

event RSVP::resvhop(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, hop_neighbor: addr)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $hop_neighbor=hop_neighbor];
	Log::write(RSVP::RSVP_Log, rec);
	#add $pkt$rsvp$hop_neighbor=hop_neighbor;
}

event RSVP::explicitrt(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, route_addr: addr)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $route_addr=route_addr];
	Log::write(RSVP::RSVP_Log, rec);
}

event RSVP::sessattr(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, attribute_name: string)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $attribute_name=attribute_name];
	Log::write(RSVP::RSVP_Log, rec);
}

event RSVP::sendertemp(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, sendertemp_addr: addr)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $sendertemp_addr=sendertemp_addr];
	Log::write(RSVP::RSVP_Log, rec);
}

event RSVP::resvconf(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, conf_receiver_addr: addr)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $conf_receiver_addr=conf_receiver_addr];
	Log::write(RSVP::RSVP_Log, rec);
}

event RSVP::filterspec(pkt: raw_pkt_hdr, version: count, rsvp_type: zeek_spicy_rsvp::MsgType, filter_sender_addr: addr)
{
	local src: addr = pkt$ip$src;
	local dst: addr = pkt$ip$dst;
	local rec: RSVP::Info = [$ts=network_time(), $version=version, $rsvp_type=MsgTypes[rsvp_type], $ip_src=src, $ip_dst=dst, $filter_sender_addr=filter_sender_addr];
	Log::write(RSVP::RSVP_Log, rec);
}



event zeek_init() &priority=5 
    {
    Log::create_stream(RSVP::RSVP_Log, [$columns=Info, $ev=log_rsvp, $path="rsvp"]);
    }