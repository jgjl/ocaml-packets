module Icmpv4_packet = struct

  type data = Cstruct.t

  let ip_protocol_no = 1

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
end

module Icmpv4_parser = struct

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

  let parse_echo buf =
    let code = Icmpv4_packet.get_icmpv4_code buf
    in let echo_buf = Cstruct.shift buf Icmpv4_packet.sizeof_icmpv4
    in let echo_id = Icmpv4_packet.get_icmpv4_echo_identifier echo_buf
    in let seq_no = Icmpv4_packet.get_icmpv4_echo_sequence_no echo_buf
    in let data = Cstruct.shift echo_buf Icmpv4_packet.sizeof_icmpv4_echo
    in
    (code, echo_id, seq_no, data)

  let parse_dst_unreachable buf =
    let code = Icmpv4_packet.get_icmpv4_code buf in
    let dst_unreach_buf = Cstruct.shift buf Icmpv4_packet.sizeof_icmpv4 in
    let next_hop_mtu = Icmpv4_packet.get_icmpv4_dst_unreachable_next_hop_mtu dst_unreach_buf in
    let embed_packet = Cstruct.shift dst_unreach_buf Icmpv4_packet.sizeof_icmpv4_dst_unreachable in
    let ip_orig_proto = Ipv4.Ipv4_packet.get_ipv4_proto embed_packet in
    let ip_orig_src = Ipv4.Ipv4_packet.get_ipv4_src embed_packet in
    let ip_orig_dst = Ipv4.Ipv4_packet.get_ipv4_dst embed_packet in
    let ip_orig_l4_data = Cstruct.shift embed_packet Ipv4.Ipv4_packet.sizeof_ipv4 in
    (code, next_hop_mtu, ip_orig_src, ip_orig_dst, ip_orig_proto, ip_orig_l4_data)

  let parse_time_exceeded buf =
    let code = Icmpv4_packet.get_icmpv4_code buf in
    let dst_unreach_buf = Cstruct.shift buf Icmpv4_packet.sizeof_icmpv4 in
    let embed_packet = Cstruct.shift dst_unreach_buf Icmpv4_packet.sizeof_icmpv4_time_exceeded in
    let ip_orig_proto = Ipv4.Ipv4_packet.get_ipv4_proto embed_packet in
    let ip_orig_src = Ipv4.Ipv4_packet.get_ipv4_src embed_packet in
    let ip_orig_dst = Ipv4.Ipv4_packet.get_ipv4_dst embed_packet in
    let ip_orig_l4_data = Cstruct.shift embed_packet Ipv4.Ipv4_packet.sizeof_ipv4 in
    (code, ip_orig_src, ip_orig_dst, ip_orig_proto, ip_orig_l4_data)

  (*
   * Lazy start: use Wikipedia for determining data structures
   * ICMP types without embedded data
   * Timestamp:            Type 13
   * Timestamp reply:      Type 14
   * Address mask request: Type 17
   * Address mask reply:   Type 18
   *)
end
