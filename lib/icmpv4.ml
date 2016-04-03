  

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
  | ADDRESSMASK_REQUEST     [@id 17]
  | ADDRESSMASK_REPLY       [@id 18]
[@@uint8_t]
]

module Wire = struct

  type t = Cstruct.t

  type part =
    | Part_icmpv4 of ty
    | Part_echo
    | Part_unused
    | Part_redirect
    | Part_timestamp
    | Part_address_mask
    | Part_bad_ip_header
    | Part_router_advertisement
    | Part_destination_unreachable
    | Part_router_advertisement_entry

  type next_part =
    | None
    | Unknown_data
    | Proto of Protocols.protocol
    | Part of part

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

  (* Router Advertisement
   * Type: 9; Code=0,16 *)
  [%%cstruct
  type part_router_advertisement = {
    advertisement_count: uint8_t;
    address_entry_size: uint8_t;
    lifetime: uint16_t;
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

  (* Router Advertisement Entry
   * Type: 9; Code=0,16 *)
  [%%cstruct
  type part_router_advertisement_entry = {
    router_address: uint32_t;
    preference_level: uint32_t;
  } [@@big_endian]
  ]

  let get_part last_part =
    match last_part with
    | Part_icmpv4 ty ->
      (match ty with
      | ECHO_REPLY | ECHO_REQUEST -> Part Part_echo
      | DESTINATION_UNREACHABLE -> Part Part_destination_unreachable
      | SOURCE_QUENCH | TIME_EXCEEDED | ROUTER_SOLICITATION -> Part Part_unused
      | REDIRECT_MESSAGE -> Part Part_redirect
      | BAD_IP_HEADER -> Part Part_bad_ip_header
      | TIMESTAMP | TIMESTAMP_REPLY -> Part Part_timestamp
      | ADDRESSMASK_REQUEST | ADDRESSMASK_REPLY -> Part Part_address_mask
      | ROUTER_ADVERTISEMENT -> Part Part_router_advertisement)
    | Part_echo -> Unknown_data
    | Part_unused | Part_redirect | Part_bad_ip_header | Part_destination_unreachable -> Proto Ipv4.Ipv4_packet.protocol_no
    | Part_timestamp | Part_address_mask -> None
    | Part_router_advertisement -> Part Part_router_advertisement_entry
    | Part_router_advertisement_entry -> None

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
      | Part_router_advertisement -> sizeof_part_router_advertisement
      | Part_router_advertisement_entry -> sizeof_part_router_advertisement_entry
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
    | Part_router_advertisement -> sizeof_part_router_advertisement + sizeof_icmpv4
    | Part_router_advertisement_entry -> sizeof_part_router_advertisement + sizeof_part_router_advertisement_entry + sizeof_icmpv4

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

