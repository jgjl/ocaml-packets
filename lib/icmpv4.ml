  

let protocol_no = Protocols.Internet (Stdint.Uint8.of_int 1)

[%%cenum
type ty =
  | ECHO_REPLY               [@id 0]
  | DESTINATION_UNREACHABLE  [@id 3]
  | SOURCE_QUENCH            [@id 4]
  | REDIRECT_MESSAGE         [@id 5]
  | ECHO_REQUEST             [@id 8]
  | ROUTER_ADVERTISEMENT     [@id 9]
  | ROUTER_SOLICITATION     [@id 10]
  | TIME_EXCEEDED           [@id 11]
  | BAD_IP_HEADER           [@id 12]
  | TIMESTAMP               [@id 13]
  | TIMESTAMP_REPLY         [@id 14]
[@@uint8_t]
]

module Wire = struct

  type t = Cstruct.t

  type part =
    | Part_echo
    | Part_unused
    | Part_redirect
    | Part_timestamp
    | Part_address_mask
    | Part_bad_ip_header
    | Part_destination_unreachable

  [%%cstruct
  type icmpv4 = {
    ty:     uint8_t;
    code:   uint8_t;
    csum:   uint16_t;
  } [@@big_endian]
  ]

  (* Echo Request/Reply
   * Type=0,8; Code=0 *)
  [%%cstruct
  type part_echo = {
    identifier: uint16_t;
    sequence_no: uint16_t;
  } [@@big_endian]
  ]

  (* Destination Unreachable
   * Type=3; Code=0-15
   *)
  [%%cstruct
  type part_unreachable = {
    unused: uint16_t;
    next_hop_mtu: uint16_t;
  } [@@big_endian]
  ]

  (* Source Quench
   * Type=4; Code=4
   * Time Exceeded
   * Type=11; Code=0,1
   *)
  [%%cstruct
  type part_unused = {
    unused: uint32_t;
  } [@@big_endian]
  ]

  (* Redirect
   * Type: 5; Code=0-3 *)
  [%%cstruct
  type part_redirect = {
    ipv4_address: uint32_t;
  } [@@big_endian]
  ]

  (* Bad IP header
   * Type: 12; Code=0-2 *)
  [%%cstruct
  type part_bad_ip_header = {
    pointer: uint8_t;
    unused: uint8_t;
    unused: uint16_t;
  } [@@big_endian]
  ]

  (* Timestamp Request/Reply
   * Type=13,14; Code=0
   *)
  [%%cstruct
  type part_timestamp = {
    identifier: uint16_t;
    sequence_no: uint16_t;
    originate_timestamp: uint32_t;
    receive_timestamp: uint32_t;
    transmit_timestamp: uint32_t;
  } [@@big_endian]
  ]

  (* Address Mask Request/Reply
   * Type=17, 18; Code=0
   *)
  [%%cstruct
  type part_address_mask = {
    address_mask: uint32_t;
  } [@@big_endian]
  ]

  let get_part ty =
    match ty with
    | 0 | 8 -> Some Part_echo
    | 3 -> Some Part_destination_unreachable
    | 4 | 11 -> Some Part_unused
    | 5 -> Some Part_redirect
    | 12 -> Some Part_bad_ip_header
    | 13 | 14 -> Some Part_timestamp
    | 17 | 18 -> Some Part_address_mask
    | _ -> None

  let get_payload_type part =
    match part with
    | Part_echo -> Protocols.Unknown
    | Part_unused | Part_redirect | Part_bad_ip_header | Part_destination_unreachable -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | Part_timestamp | Part_address_mask -> Protocols.None

  let get_part v =
    if (Cstruct.len v) > 4 
    then Some (Cstruct.shift v 4)
    else None

  let get_payload part v =
    let shiftlen = match part with
      | Part_echo -> sizeof_part_echo
      | Part_unused -> sizeof_part_unused
      | Part_redirect -> sizeof_part_redirect
      | Part_destination_unreachable -> sizeof_part_unreachable
      | Part_timestamp -> sizeof_part_timestamp
      | Part_address_mask -> sizeof_part_address_mask
      | Part_bad_ip_header -> sizeof_part_bad_ip_header
    in
    if (Cstruct.len v) > shiftlen 
    then Some (Cstruct.shift v shiftlen)
    else None

  let get_icmpv_hdr_len part =
    match part with
    | Part_echo -> sizeof_part_echo + sizeof_icmpv4
    | Part_unused -> sizeof_part_unused + sizeof_icmpv4
    | Part_redirect -> sizeof_part_redirect + sizeof_icmpv4
    | Part_destination_unreachable -> sizeof_part_unreachable + sizeof_icmpv4
    | Part_timestamp -> sizeof_part_timestamp + sizeof_icmpv4
    | Part_address_mask -> sizeof_part_address_mask + sizeof_icmpv4
    | Part_bad_ip_header -> sizeof_part_bad_ip_header + sizeof_icmpv4

  let is_valid v ty code part =
    let type_code_ok = match ty with
    | 0 when code = 0 -> true
    | 3 when code < 16 -> true
    | 5 when code < 4 -> true
    | 8 when code = 0 -> true
    | 9 when code = 0 -> true
    | 10 when code = 0 -> true
    | 11 when code = 0 -> true
    | 12 when code < 3 -> true
    | 13 when code = 0 -> true
    | 14 when code = 0 -> true
    (* Deprecated *)
    | 4 when code = 0 -> true
    | 15 when code = 0 -> true
    | 16 when code = 0 -> true
    | 17 when code = 0 -> true
    | 18 when code = 0 -> true
    (* Unused *)
    | _ -> false
    in
    let length_ok = (get_icmpv_hdr_len part) <= Cstruct.len v in
    (* let csum_ok = ... *)
    type_code_ok && length_ok

  (*TODO: Checksum calculation *)
end



module Parser = struct

  type fields =
    | Type
    | Code
    | Csum
    | Identifier
    | Sequence_no
    | Next_hop_mtu
    | Payload

  type icmpv4 = {
    ty: Stdint.uint8;
    code: Stdint.uint8;
    csum: Stdint.uint16;
  }

  type option_unreachable = {
    ip_orig_proto: Stdint.uint8;
  }

  type option_unreachable_too_big = {
    next_hop_mtu: Stdint.uint8;
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

  (* Based on Wikipedia *cough* *)
  let type_to_string ty code =
    match ty with
    | ECHO_REPLY when code=0 -> Some "Echo reply"
    | ECHO_REQUEST when code=0 -> Some "Echo request"
    | DESTINATION_UNREACHABLE when code < 16->
      (let msg = "Redirect message: " in
      match code with
      | 0  -> Some (msg ^ "Destination network unreachable")
      | 1  -> Some (msg ^ "Destination host unreachable")
      | 2  -> Some (msg ^ "Destination protocol unreachable")
      | 3  -> Some (msg ^ "Destination port unreachable")
      | 4  -> Some (msg ^ "Fragmentation required, and DF flag set")
      | 5  -> Some (msg ^ "Source route failed")
      | 6  -> Some (msg ^ "Destination network unknown")
      | 7  -> Some (msg ^ "Destination host unknown")
      | 8  -> Some (msg ^ "Source host isolated")
      | 9  -> Some (msg ^ "Network administratively prohibited")
      | 10 -> Some (msg ^ "Host administratively prohibited")
      | 11 -> Some (msg ^ "Network unreachable for TOS")
      | 12 -> Some (msg ^ "Host unreachable for TOS")
      | 13 -> Some (msg ^ "Communication administratively prohibited")
      | 14 -> Some (msg ^ "Host Precedence Violation")
      | 15 -> Some (msg ^ "Precedence cutoff in effect"))
    | SOURCE_QUENCH when code=0 -> Some "Source quench (message type is deprecated!)"
    | REDIRECT_MESSAGE when code<4->
      (let msg = "Redirect message: " in
      match code with
      | 0 -> Some (msg ^ "Redirect for Network")
      | 1 -> Some (msg ^ "Redirect for Host")
      | 2 -> Some (msg ^ "Redirect for Type of Service and Network")
      | 3 -> Some (msg ^ "Redirect for Type of Service and Host"))
    | ROUTER_ADVERTISEMENT when code=0 -> Some "Router advertisement"
    | ROUTER_SOLICITATION when code=0 -> Some "Router solicitation"
    | TIME_EXCEEDED when code=0 -> Some "Router solicitation"
    | BAD_IP_HEADER when code<3 ->
      (let msg = "Bad IP header: " in
      match code with
      | 0 -> Some (msg ^ "Pointer indicates this error")
      | 1 -> Some (msg ^ "Missing a required option")
      | 2 -> Some (msg ^ "Bad length"))
    | TIMESTAMP when code=0 -> Some "Timestamp"
    | TIMESTAMP_REPLY when code=0 -> Some "Timestamp reply"
    | _ -> None

  (*
  type structure =
    | Field of fields
    | Option of fields list
    | Payload of Protocols.next_protocol

  type icmpv4_msg =
    | Dst_unreachable of icmpv4_unreachable * Cstruct.t
    | Dst_unreachable_too_big of icmpv4_unreachable_too_big * Cstruct.t
    | Echo_request of icmpv4_echo
    | Echo_reply of icmpv4_echo
    | Time_exceeded of icmpv4_time_exceeded * Cstruct.t

  type part = {
    name: string;
    fields: fields list;
    length: int;
  }
  let get_fields part =
    match part with
    | Icmpv4 -> {fields = [Type, Code, Csum], length = 4}
    | Opt_unreachable_too_big -> {fields=[Next_hop_mtu], length = 4}
    | Opt_unreachable -> {fields = [], length = 4}
    | Opt_echo -> {fields = [Identifier; Sequence_no]; length = 4}
    | Opt_unknown -> {fields = []; length = 4}

  let get_field field v =
    match field with
    | Type -> Cstruct.get_uint8 v 0
    | Code -> Cstruct.get_uint8 v 1
    | Csum -> Cstruct.BE.get_uint16 v 2
    | Identifier -> Cstruct.BE.get_uint16 v 0
    | Sequence_no ->  Cstruct.BE.get_uint16 v 2
    | Next_hop_mtu -> Some (Cstruct.BE.get_uint16 v 2)

  let get_option (icmpv4_type, icmpv4_code) field v =
    match field, icmpv4_type, icmpv4_code with
    | Identifier, 0, 0 | Identifier, 8, 0 -> Some (Cstruct.BE.get_uint16 v 4)
    | Sequence_no, 0, 0 | Sequence_no, 8, 0 -> Some (Cstruct.BE.get_uint16 v 6)
    | Next_hop_mtu, 3, 4 -> Some (Cstruct.BE.get_uint16 v 6)
    | _, _, _ -> None

  let fields = [Type, Code, Csum]

  (*
  let next_part current_part v =
    | 3, 4 -> [Field Type; Field Code; Field Csum; OptionalField Next_hop_mtu; Payload (Protocols.Protocol Ipv4.Ipv4_packet.protocol_no)]
    | 3, _ -> [Field Type; Field Code; Field Csum; Payload (Protocols.Protocol Ipv4.Ipv4_packet.protocol_no)]
    | 0, 0 | 8, 0 -> [Field Type; Field Code; Field Csum; OptionalField Identifier; OptionalField Sequence_no; Payload Protocols.Unknown]
    | _, _ -> [Field Type; Field Code; Field Csum]
    *)


  let get_payload icmpv4_type icmpv4_code v =
    match icmpv4_type, icmpv4_code with
    (*| Stdint.Uint8.zero, Stdint.Uint8.zero -> Cstruct.shift v 4*)
    | 3,_ -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no, Some (Cstruct.shift v 8)
    | 8,0 | 0,0 -> Protocols.Unknown, Some (Cstruct.shift v 8)
    | _, _ -> Protocols.None, None
    *)
end
