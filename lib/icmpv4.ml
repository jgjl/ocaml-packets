

module Icmpv4_packet = struct

  type data = Cstruct.t

  let protocol_no = Protocols.Internet (Stdint.Uint8.of_int 1)

  (*
   * Lazy start: use Wikipedia for determining data structures
   * ICMP types without embedded data
   * Timestamp:            Type 13
   * Timestamp reply:      Type 14
   * Address mask request: Type 17
   * Address mask reply:   Type 18
   *)

  type fields =
    | Type
    | Code
    | Csum

  type optional_fields =
    | Identifier
    | Sequence_no
    | Next_hop_mtu
    | Payload

  type field_list =
    | Field of fields
    | OptionalField of optional_fields
    | Payload of Protocols.next_protocol

  let sizeof_icmpv = 4

  let get_field_list icmpv4_type icmpv4_code =
    match icmpv4_type, icmpv4_code with
    | 3, 4 -> [Field Type; Field Code; Field Csum; OptionalField Next_hop_mtu; Payload (Protocols.Protocol Ipv4.Ipv4_packet.protocol_no)]
    | 3, _ -> [Field Type; Field Code; Field Csum; Payload (Protocols.Protocol Ipv4.Ipv4_packet.protocol_no)]
    | 0, 0 | 8, 0 -> [Field Type; Field Code; Field Csum; OptionalField Identifier; OptionalField Sequence_no; Payload Protocols.Unknown]
    | _, _ -> [Field Type; Field Code; Field Csum]

  let get_field field v =
    match field with
    | Type -> Cstruct.get_uint8 v 0
    | Code -> Cstruct.get_uint8 v 1
    | Csum -> Cstruct.BE.get_uint16 v 2

  let get_optional_field icmpv4_type icmpv4_code field v =
    match field, icmpv4_type, icmpv4_code with
    | Identifier, 0, 0 | Identifier, 8, 0 -> Some (Cstruct.BE.get_uint16 v 4)
    | Sequence_no, 0, 0 | Sequence_no, 8, 0 -> Some (Cstruct.BE.get_uint16 v 6)
    | Next_hop_mtu, 3, 4 -> Some (Cstruct.BE.get_uint16 v 6)
    | _, _, _ -> None

  let get_payload icmpv4_type icmpv4_code v =
    match icmpv4_type, icmpv4_code with
    (*| Stdint.Uint8.zero, Stdint.Uint8.zero -> Cstruct.shift v 4*)
    | 3,_ -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no, Some (Cstruct.shift v 8)
    | 8,0 | 0,0 -> Protocols.Unknown, Some (Cstruct.shift v 8)
    | _, _ -> Protocols.None, None
end

module Icmpv4_parser = struct
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

  type icmpv4_unreachable = {
    code: Stdint.uint8;
    ip_orig_src: Stdint.uint32;
    ip_orig_dst: Stdint.uint32;
    ip_orig_proto: Stdint.uint8;
  }

  type icmpv4_unreachable_too_big = {
    code: Stdint.uint8;
    next_hop_mtu: Stdint.uint8;
    ip_orig_src: Stdint.uint32;
    ip_orig_dst: Stdint.uint32;
    ip_orig_proto: Stdint.uint8
    }

  type icmpv4_echo = {
    identifier: int;
    sequence_number: int;
    data: Cstruct.t;
  }

  type icmpv4_time_exceeded = {
    code: int;
    ip_orig_src: Stdint.uint32;
    ip_orig_dst: Stdint.uint32;
    ip_orig_proto: int
  }

  type icmpv4_msg =
    | Dst_unreachable of icmpv4_unreachable * Cstruct.t
    | Dst_unreachable_too_big of icmpv4_unreachable_too_big * Cstruct.t
    | Echo_request of icmpv4_echo
    | Echo_reply of icmpv4_echo
    | Time_exceeded of icmpv4_time_exceeded * Cstruct.t

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
end
