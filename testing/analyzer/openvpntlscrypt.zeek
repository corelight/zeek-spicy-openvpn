# @TEST-EXEC: zeek -C -r ${TRACES}/openvpn_udp_tlscrypt.pcap %INPUT >openvpn.out
# @TEST-EXEC: zeek-cut -m -n local_orig local_resp ip_proto < conn.log > conn.log.filtered
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log.filtered

@load analyzer

redef OpenVPN::disable_analyzer_after_detection = F;

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg) { print cat(msg); }
event OpenVPN::control_message_with_data(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg, ssl_data: string) { print cat(msg); }
event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::AckMsg) { print cat(msg); }
event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg) { print cat(msg); }
