# @TEST-REQUIRES: test -e ${TRACES}/trace.pcap
# @TEST-EXEC: zeek -r ${TRACES}/trace.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test OpenVPN against Zeek with a small trace.

@load analyzer

# TODO: This test needs to work on a specific trace.
