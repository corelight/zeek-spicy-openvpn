# zeek-spicy-openvpn

This is a protocol analyzer that detects OpenVPN traffic.
You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

Blogs and webinars detailing the development of this protocol analyzer:

- <https://zeek.org/2021/03/16/a-zeek-openvpn-protocol-analyzer/>
- <https://zeek.org/2021/04/08/a-zeek-openvpn-protocol-analyzer-in-spicy/>
- <https://event.webinarjam.com/replay/16/405xvaqawfzfqn>
  - Slides: <https://docs.google.com/presentation/d/1ftvMeQ-9hyeozTLXyO_CLVHDLGiwbJk9SqCp8laD1FM/edit?usp=sharing>

## Example Log

```
$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2022-01-21-11-46-35
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1613755368.960989	CyO1lb37w2czkxBsPd	192.168.88.3	50568	46.246.122.61	1198	udp	ssl,spicy_openvpn_udp	44.271572	5825	8524	SF	-	-	0	Dd	57	7421	48	9868	-
#close	2022-01-21-11-46-35

$ cat ssl.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	2022-01-21-11-46-35
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fps	client_cert_chain_fps	sni_matches_cert	ja3	ja3s
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	string	vector[string]	vector[string]	bool	string	string
1613755369.067702	CyO1lb37w2czkxBsPd	192.168.88.3	50568	46.246.122.61	1198	TLSv13	TLS_AES_256_GCM_SHA384	x25519	-	F	-	-	T	CsiI	-	-	-	c81fc162549590f0e836b538fe5bfdd7	15af977ce25de452b96affa2addb1036
#close	2022-01-21-11-46-35
```

## Sample PCAPs

- [openvpn-tcp-tls-auth.pcap](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=OpenVPN_TCP_tls-auth.pcapng)
- openvpn.pcap (self-made)
- openvpn_udp_hmac_256.pcap (self-made)
- [openvpn_tcp_nontlsauth.pcap](https://bugs.wireshark.org/bugzilla/attachment.cgi?id=9840)
- [openvpn_udp_tls-auth.pcap](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=OpenVPN_UDP_tls-auth.pcapng)
