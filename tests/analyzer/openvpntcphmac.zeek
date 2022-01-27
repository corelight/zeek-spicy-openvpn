# @TEST-EXEC: zeek -C -r ${TRACES}/openvpn-tcp-tls-auth.pcap %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log

@load analyzer

redef OpenVPN_2::disable_analyzer_after_detection = F;

event OpenVPN_2::control_message(c: connection, is_orig: bool, msg: OpenVPN_2::ControlMsg) { print cat(msg); }
event OpenVPN_2::ack_message(c: connection, is_orig: bool, msg: OpenVPN_2::AckMsg) { print cat(msg); }
event OpenVPN_2::data_message(c: connection, is_orig: bool, msg: OpenVPN_2::DataMsg) { print cat(msg); }
