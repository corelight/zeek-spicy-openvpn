signature dpd_openvpn_udp_client_2 {
  ip-proto == udp
  payload /^\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_udp_server_2 {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpn_udp_client_2
  enable "spicy_OpenVPN_UDP_2"
}

signature dpd_openvpnhmacmd5_udp_client_2 {
  ip-proto == udp
  payload /^\x38.{32}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacmd5_udp_server_2 {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacmd5_udp_client_2
  enable "spicy_OpenVPN_UDP_HMAC_MD5_2"
}

signature dpd_openvpnhmacsha1_udp_client_2 {
  ip-proto == udp
  payload /^\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha1_udp_server_2 {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha1_udp_client_2
  enable "spicy_OpenVPN_UDP_HMAC_SHA1_2"
}

signature dpd_openvpnhmacsha256_udp_client_2 {
  ip-proto == udp
  payload /^\x38.{48}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha256_udp_server_2 {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_udp_client_2
  enable "spicy_OpenVPN_UDP_HMAC_SHA256_2"
}

signature dpd_openvpnhmacsha512_udp_client_2 {
  ip-proto == udp
  payload /^\x38.{80}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha512_udp_server_2 {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha512_udp_client_2
  enable "spicy_OpenVPN_UDP_HMAC_SHA512_2"
}

signature dpd_openvpn_tcp_client_2 {
  ip-proto == tcp
  payload /^..\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_tcp_server_2 {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpn_tcp_client_2
  enable "spicy_OpenVPN_TCP_2"
}

signature dpd_openvpnhmacmd5_tcp_client_2 {
  ip-proto == tcp
  payload /^..\x38.{32}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacmd5_tcp_server_2 {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacmd5_tcp_client_2
  enable "spicy_OpenVPN_TCP_HMAC_MD5_2"
}

signature dpd_openvpnhmacsha1_tcp_client_2 {
  ip-proto == tcp
  payload /^..\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha1_tcp_server_2 {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha1_tcp_client_2
  enable "spicy_OpenVPN_TCP_HMAC_SHA1_2"
}

signature dpd_openvpnhmacsha256_tcp_client_2 {
  ip-proto == tcp
  payload /^..\x38.{48}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha256_tcp_server_2 {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_tcp_client_2
  enable "spicy_OpenVPN_TCP_HMAC_SHA256_2"
}

signature dpd_openvpnhmacsha512_tcp_client_2 {
  ip-proto == tcp
  payload /^..\x38.{80}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha512_tcp_server_2 {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha512_tcp_client_2
  enable "spicy_OpenVPN_TCP_HMAC_SHA512_2"
}
