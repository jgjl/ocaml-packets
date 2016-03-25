
[%%cstruct
type ethernet = {
    dst: uint8_t        [@len 6];
    src: uint8_t        [@len 6];
    ethertype: uint16_t;
  } [@@big_endian]
]

[%%cenum
type ethertype =
  | ARP  [@id 0x0806]
  | IPv4 [@id 0x0800]
  | IPv6 [@id 0x86dd]
  [@@uint16_t]
]

let parse_ethernet_frame frame =
  if Cstruct.len frame >= 14 then
    (* source + destination + type = 14 *)
    let payload = Cstruct.shift frame sizeof_ethernet
    and typ = get_ethernet_ethertype frame
    and dst = Macaddr.of_bytes_exn (copy_ethernet_dst frame)
    in
    Some (int_to_ethertype typ, dst, payload)
  else
    None

  [%%cstruct
  type udp = {
      source_port: uint16_t;
      dest_port: uint16_t;
      length: uint16_t;
      checksum: uint16_t;
    } [@@big_endian]
  ]

module Ipv4_wire = struct
  [%%cstruct
  type ipv4 = {
      hlen_version: uint8_t;
      tos:          uint8_t;
      len:          uint16_t;
      id:           uint16_t;
      off:          uint16_t;
      ttl:          uint8_t;
      proto:        uint8_t;
      csum:         uint16_t;
      src:          uint32_t;
      dst:          uint32_t;
    } [@@big_endian]
  ]

  let int_to_protocol = function
    | 1  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let protocol_to_int = function
    | `ICMP   -> 1
    | `TCP    -> 6
    | `UDP    -> 17

  (* [checksum packet bufs] computes the IP checksum of [bufs]
      computing the pseudo-header from the actual header [packet]
      (which does NOT include the link-layer part). *)
  let checksum =
    let pbuf = Io_page.to_cstruct (Io_page.get 1) in
    let pbuf = Cstruct.set_len pbuf 4 in
    Cstruct.set_uint8 pbuf 0 0;
    fun packet bufs ->
      Cstruct.set_uint8 pbuf 1 (get_ipv4_proto packet);
      Cstruct.BE.set_uint16 pbuf 2 (Cstruct.lenv bufs);
      let src_dst = Cstruct.sub packet 12 (2 * 4) in
      Tcpip_checksum.ones_complement_list (src_dst :: pbuf :: bufs)
end

module Icmpv4_wire = struct

  type data = Cstruct.t

  (*
   * Implemented ICMPv4 types
   *
   * ICMPv4 "Echo Request"
   * Type 8
   * Code 0
   *
   * ICMPv4 "Echo Reply"
   * Type 0
   * Code 0
   *
   * ICMPv4 "Destination Unreachable"
   * Type 3
   * Codes
   *
   * ICMPv4 "Time Exceeded"
   * Type 11
   * Codes
   *   0	Time-to-live exceeded in transit.
   *   1	Fragment reassembly time exceeded.
  *)

  let icmpv4_dst_unreachable code =
    match code with
    | 0  -> "Destination network unreachable"
    | 1  -> "Destination host unreachable"
    | 2  -> "Destination protocol unreachable"
    | 3  -> "Destination port unreachable"
    | 4  -> "Fragmentation required, and DF flag set"
    | 5  -> "Source route failed"
    | 6  -> "Destination network unknown"
    | 7  -> "Destination host unknown"
    | 8  -> "Source host isolated"
    | 9  -> "Network administratively prohibited"
    | 10 -> "Host administratively prohibited"
    | 11 -> "Network unreachable for TOS"
    | 12 -> "Host unreachable for TOS"
    | 13 -> "Communication administratively prohibited"
    | 14 -> "Host Precedence Violation"
    | 15 -> "Precedence cutoff in effect"
    | code_no -> "Unknown ICMP code: " ^ string_of_int(code)

  [%%cstruct
  type icmpv4 = {
    ty: uint8_t;
    code: uint8_t;
    csum: uint16_t;
  } [@@big_endian]
  ]

  [%%cstruct
  type icmpv4_echo = {
    identifier: uint16_t;
    sequence_no: uint16_t;
  } [@@big_endian]
  ]

  [%%cstruct
  type icmpv4_time_exceeded = {
    unused: uint32_t;
  } [@@big_endian]
  ]

  [%%cstruct
  type icmpv4_dst_unreachable = {
    unused: uint16_t;
    next_hop_mtu: uint16_t;
  } [@@big_endian]
  ]

  let parse_echo buf =
    let code = get_icmpv4_code buf
    in let echo_buf = Cstruct.shift buf sizeof_icmpv4
    in let echo_id = get_icmpv4_echo_identifier echo_buf
    in let seq_no = get_icmpv4_echo_sequence_no echo_buf
    in let data = Cstruct.shift echo_buf sizeof_icmpv4_echo
    in
    (code, echo_id, seq_no, data)

  let parse_dst_unreachable buf =
    let code = get_icmpv4_code buf in
    let dst_unreach_buf = Cstruct.shift buf sizeof_icmpv4 in
    let next_hop_mtu = get_icmpv4_dst_unreachable_next_hop_mtu dst_unreach_buf in
    let embed_packet = Cstruct.shift dst_unreach_buf sizeof_icmpv4_dst_unreachable in
    let ip_orig_proto = Ipv4_wire.get_ipv4_proto embed_packet in
    let ip_orig_src = Ipv4_wire.get_ipv4_src embed_packet in
    let ip_orig_dst = Ipv4_wire.get_ipv4_dst embed_packet in
    let ip_orig_l4_data = Cstruct.shift embed_packet Ipv4_wire.sizeof_ipv4 in
    (code, next_hop_mtu, ip_orig_src, ip_orig_dst, ip_orig_proto, ip_orig_l4_data)

  let parse_time_exceeded buf =
    let code = get_icmpv4_code buf in
    let dst_unreach_buf = Cstruct.shift buf sizeof_icmpv4 in
    let embed_packet = Cstruct.shift dst_unreach_buf sizeof_icmpv4_time_exceeded in
    let ip_orig_proto = Ipv4_wire.get_ipv4_proto embed_packet in
    let ip_orig_src = Ipv4_wire.get_ipv4_src embed_packet in
    let ip_orig_dst = Ipv4_wire.get_ipv4_dst embed_packet in
    let ip_orig_l4_data = Cstruct.shift embed_packet Ipv4_wire.sizeof_ipv4 in
    (code, ip_orig_src, ip_orig_dst, ip_orig_proto, ip_orig_l4_data)

  (*
   * Lazy start: use Wikipedia for determining data structures
   * ICMP types without embedded data
   * Timestamp:            Type 13
   * Timestamp reply:      Type 14
   * Address mask request: Type 17
   * Address mask reply:   Type 18
   *)

  let checksum =
    let pbuf = Io_page.to_cstruct (Io_page.get 1) in
    let pbuf = Cstruct.set_len pbuf 4 in
    Cstruct.set_uint8 pbuf 0 0;
    fun packet bufs ->
      Cstruct.BE.set_uint16 pbuf 2 (Cstruct.lenv bufs);
      let src_dst = Cstruct.sub packet 12 (2 * 4) in
      Tcpip_checksum.ones_complement_list (src_dst :: pbuf :: bufs)
end

module Tcp_wire = struct
  [%%cstruct
  type tcp = {
      src_port:   uint16_t;
      dst_port:   uint16_t;
      sequence:   uint32_t;
      ack_number: uint32_t;
      dataoff:    uint8_t;
      flags:      uint8_t;
      window:     uint16_t;
      checksum:   uint16_t;
      urg_ptr:    uint16_t;
    } [@@big_endian]
  ]

  [%%cstruct
  type tcpv4_pseudo_header = {
      src:   uint32_t;
      dst:   uint32_t;
      res:   uint8_t;
      proto: uint8_t;
      len:   uint16_t;
    } [@@big_endian]
  ]

  (* XXX note that we overwrite the lower half of dataoff
   * with 0, so be careful when implemented CWE flag which
   * sits there *)
  let get_data_offset buf = ((get_tcp_dataoff buf) lsr 4) * 4
  let set_data_offset buf v = set_tcp_dataoff buf (v lsl 4)

  let get_fin buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 0)) > 0
  let get_syn buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 1)) > 0
  let get_rst buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 2)) > 0
  let get_psh buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 3)) > 0
  let get_ack buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 4)) > 0
  let get_urg buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 5)) > 0
  let get_ece buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 6)) > 0
  let get_cwr buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 7)) > 0

  let set_fin buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 0))
  let set_syn buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 1))
  let set_rst buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 2))
  let set_psh buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 3))
  let set_ack buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 4))
  let set_urg buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 5))
  let set_ece buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 6))
  let set_cwr buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 7))
end

module Ipv6_wire = struct
  [%%cstruct
  type ipv6 = {
      version_flow: uint32_t;
      len:          uint16_t;  (* payload length (includes extensions) *)
      nhdr:         uint8_t; (* next header *)
      hlim:         uint8_t; (* hop limit *)
      src:          uint8_t [@len 16];
      dst:          uint8_t [@len 16];
    } [@@big_endian]
  ]

  let int_to_protocol = function
    | 58  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let protocol_to_int = function
    | `ICMP   -> 58
    | `TCP    -> 6
    | `UDP    -> 17

  [%%cstruct
  type icmpv6 = {
      ty:       uint8_t;
      code:     uint8_t;
      csum:     uint16_t;
      reserved: uint32_t;
    } [@@big_endian]
  ]

  [%%cstruct
  type pingv6 = {
      ty:   uint8_t;
      code: uint8_t;
      csum: uint16_t;
      id:   uint16_t;
      seq:  uint16_t;
    } [@@big_endian]
  ]
  [%%cstruct
  type ns = {
      ty:       uint8_t;
      code:     uint8_t;
      csum:     uint16_t;
      reserved: uint32_t;
      target:   uint8_t  [@len 16];
    } [@@big_endian]
  ]
  [%%cstruct
  type na = {
      ty: uint8_t;
      code: uint8_t;
      csum: uint16_t;
      reserved: uint32_t;
      target: uint8_t [@len 16];
    } [@@big_endian]
  ]
  let get_na_router buf =
    (Cstruct.get_uint8 buf 4 land 0x80) <> 0

  let get_na_solicited buf =
    (Cstruct.get_uint8 buf 4 land 0x40) <> 0

  let get_na_override buf =
    (Cstruct.get_uint8 buf 4 land 0x20) <> 0

  [%%cstruct
  type rs = {
      ty:       uint8_t;
      code:     uint8_t;
      csum:     uint16_t;
      reserved: uint32_t;
    } [@@big_endian]
  ]
  [%%cstruct
  type opt_prefix = {
      ty:                 uint8_t;
      len:                uint8_t;
      prefix_len:         uint8_t;
      reserved1:          uint8_t;
      valid_lifetime:     uint32_t;
      preferred_lifetime: uint32_t;
      reserved2:          uint32_t;
      prefix:             uint8_t [@len 16];
    } [@@big_endian]
  ]
  let get_opt_prefix_on_link buf =
    get_opt_prefix_reserved1 buf land 0x80 <> 0

  let get_opt_prefix_autonomous buf =
    get_opt_prefix_reserved1 buf land 0x40 <> 0

  [%%cstruct
  type opt = {
      ty:  uint8_t;
      len: uint8_t;
    } [@@big_endian]
  ]
  [%%cstruct
  type llopt = {
      ty:   uint8_t;
      len:  uint8_t;
      addr: uint8_t [@len 6];
    } [@@big_endian]
  ]

  [%%cstruct
  type ra = {
      ty:              uint8_t;
      code:            uint8_t;
      csum:            uint16_t;
      cur_hop_limit:   uint8_t;
      reserved:        uint8_t;
      router_lifetime: uint16_t;
      reachable_time:  uint32_t;
      retrans_timer:   uint32_t;
    } [@@big_endian]
  ]
  let sizeof_ipv6_pseudo_header = 16 + 16 + 4 + 4
end
