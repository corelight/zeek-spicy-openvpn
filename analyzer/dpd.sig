signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /^\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpn_udp_client
  enable "spicy_OpenVPN_UDP"
}

signature dpd_openvpnhmacmd5_udp_client {
  ip-proto == udp
  payload /^\x38.{32}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacmd5_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacmd5_udp_client
  enable "spicy_OpenVPN_UDP_HMAC_MD5"
}

signature dpd_openvpnhmacsha1_udp_client {
  ip-proto == udp
  payload /^\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha1_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha1_udp_client
  enable "spicy_OpenVPN_UDP_HMAC_SHA1"
}

signature dpd_openvpnhmacsha256_udp_client {
  ip-proto == udp
  payload /^\x38.{48}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha256_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_udp_client
  enable "spicy_OpenVPN_UDP_HMAC_SHA256"
}

# TLS-crypt-v2 only: P_CONTROL_HARD_RESET_CLIENT_V3 (opcode 10, 0x50) is unique to v2.
# TLS-crypt-v1 cannot be reliably detected: it shares opcode 7 (0x38) with other modes
# and its encrypted payload leaves no distinguishable pattern for DPD.
signature dpd_openvpnhmacsha256_tlscrypt_v2_udp_client {
  ip-proto == udp
  payload /^\x50/
}

signature dpd_openvpnhmacsha256_tlscrypt_v2_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_tlscrypt_v2_udp_client
  enable "spicy_OpenVPN_UDP_HMAC_SHA256"
}

signature dpd_openvpnhmacsha512_udp_client {
  ip-proto == udp
  payload /^\x38.{80}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha512_udp_server {
  ip-proto == udp
  payload /^\x40/
  requires-reverse-signature dpd_openvpnhmacsha512_udp_client
  enable "spicy_OpenVPN_UDP_HMAC_SHA512"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpn_tcp_client
  enable "spicy_OpenVPN_TCP"
}

signature dpd_openvpnhmacmd5_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{32}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacmd5_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacmd5_tcp_client
  enable "spicy_OpenVPN_TCP_HMAC_MD5"
}

signature dpd_openvpnhmacsha1_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha1_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha1_tcp_client
  enable "spicy_OpenVPN_TCP_HMAC_SHA1"
}

signature dpd_openvpnhmacsha256_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{48}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha256_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_tcp_client
  enable "spicy_OpenVPN_TCP_HMAC_SHA256"
}

# TLS-crypt-v2 only: see UDP equivalent for explanation.
signature dpd_openvpnhmacsha256_tlscrypt_v2_tcp_client {
  ip-proto == tcp
  payload /^..\x50/
}

signature dpd_openvpnhmacsha256_tlscrypt_v2_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha256_tlscrypt_v2_tcp_client
  enable "spicy_OpenVPN_TCP_HMAC_SHA256"
}

signature dpd_openvpnhmacsha512_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{80}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmacsha512_tcp_server {
  ip-proto == tcp
  payload /^..\x40/
  requires-reverse-signature dpd_openvpnhmacsha512_tcp_client
  enable "spicy_OpenVPN_TCP_HMAC_SHA512"
}
