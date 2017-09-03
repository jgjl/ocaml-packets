
module Option : sig
  val bind : 'a option -> ('a -> 'b option) -> 'b option
  val (>>=) : 'a option -> ('a -> 'b option) -> 'b option
  val return : 'a -> 'a option
end = struct
  let bind x f = match x with
  | Some x -> f x
  | None -> None
  let return x = Some x
  let (>>=) = bind
end

let protocol_no = Protocols.Internet (Stdint.Uint8.of_int 1)

module WireV2 = struct

  type t = Cstruct.t

  [%%cstruct
  type header = {
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
   * Router Solicitation
   * Type=10; Code=0
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

  [%%cenum
  type destination_unreachable_code =
    | Destination_network_unreachable           [@id0]
    | Destination_host_unreachable              [@id1]
    | Destination_protocol_unreachable          [@id2]
    | Destination_port_unreachable              [@id3]
    | Fragmentation_required_and_DF_flag_set    [@id4]
    | Source_route_failed                       [@id5]
    | Destination_network_unknown               [@id6]
    | Destination_host_unknown                  [@id7]
    | Source_host_isolated                      [@id8]
    | Network_administratively_prohibited       [@id9]
    | Host_administratively_prohibited          [@id10]
    | Network_unreachable_for_TOS               [@id11]
    | Host_unreachable_for_TOS                  [@id12]
    | Communication_administratively_prohibited [@id13]
    | Host_Precedence_Violation                 [@id14]
    | Precedence_cutoff_in_effect               [@id15]
  [@@uint8_t] ]

  [%%cenum
  type redirect_message_code =
    | Network_error         [@id 0]
    | Host_error            [@id 1]
    | TOS_and_network_error [@id 2]
    | TOS_and_host_error    [@id 3]
  [@@uint8_t] ]

  [%%cenum
  type router_advertisement_code =
    | Normal_router_advertisement   [@id 0]
    | Does_not_route_common_traffic [@id 16]
  [@@uint8_t] ]

  [%%cenum
  type time_exceeded_code =
    | Time_to_live_equals_0_during_transit [@id 0]
    | Fragment_reassembly_timeout          [@id 1]
  [@@uint8_t] ]

  [%%cenum
  type bad_ip_header_code =
    | Invalid_IP_header             [@id 0]
    | A_required_option_is_missing  [@id 1]
  [@@uint8_t] ]

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
  [@@uint8_t] ]

  [%%cenum
  type default_code =
    | ZERO                     [@id 0]
  [@@uint8_t] ]
  let sizeof_part_router_advertisement_total v =
    let v_part = Cstruct.shift v sizeof_header in
    let count = get_part_router_advertisement_advertisement_count v_part in
    let size = get_part_router_advertisement_address_entry_size v_part in
    size * count + sizeof_part_router_advertisement

  type _ code =
    | ECHO_REPLY_CODE : default_code -> default_code code
    | DESTINATION_UNREACHABLE_CODE : destination_unreachable_code -> destination_unreachable_code code
    | SOURCE_QUENCH_CODE: default_code -> default_code code
    | REDIRECT_MESSAGE_CODE: redirect_message_code -> redirect_message_code code
    | ECHO_REQUEST_CODE: default_code -> default_code code
    | ROUTER_ADVERTISEMENT_CODE: router_advertisement_code -> router_advertisement_code code
    | ROUTER_SOLICITATION_CODE: default_code -> default_code code
    | TIME_EXCEEDED_CODE: time_exceeded_code -> time_exceeded_code code
    | BAD_IP_HEADER_CODE: bad_ip_header_code -> bad_ip_header_code code
    | TIMESTAMP_CODE: default_code -> default_code code
    | TIMESTAMP_REPLY_CODE: default_code -> default_code code

  let sizeof_ty ty v =
    sizeof_header + match ty with
    | ECHO_REPLY -> sizeof_part_echo
    | DESTINATION_UNREACHABLE -> sizeof_part_unreachable
    | SOURCE_QUENCH -> sizeof_part_unused
    | REDIRECT_MESSAGE -> sizeof_part_redirect
    | ECHO_REQUEST -> sizeof_part_echo
    | ROUTER_ADVERTISEMENT -> sizeof_part_router_advertisement_total v
    | ROUTER_SOLICITATION -> sizeof_part_unused
    | TIME_EXCEEDED -> sizeof_part_unused
    | BAD_IP_HEADER -> sizeof_part_bad_ip_header
    | TIMESTAMP -> sizeof_part_timestamp
    | TIMESTAMP_REPLY -> sizeof_part_timestamp

  let next_protocol ty code v =
    match ty with
    | ECHO_REPLY -> Protocols.Unknown
    | DESTINATION_UNREACHABLE -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | SOURCE_QUENCH -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | REDIRECT_MESSAGE -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | ECHO_REQUEST -> Protocols.Unknown
    | ROUTER_ADVERTISEMENT -> Protocols.None
    | ROUTER_SOLICITATION -> Protocols.None
    | TIME_EXCEEDED -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | BAD_IP_HEADER -> Protocols.Protocol Ipv4.Ipv4_packet.protocol_no
    | TIMESTAMP -> Protocols.None
    | TIMESTAMP_REPLY -> Protocols.None

  let int_to_code_fun ty =
    match ty with
    | ECHO_REPLY -> int_to_default_code
    | DESTINATION_UNREACHABLE -> int_to_destination_unreachable_code
    | SOURCE_QUENCH -> int_to_destination_unreachable_code
    | REDIRECT_MESSAGE -> int_to_redirect_message_code
    | ECHO_REQUEST -> int_to_default_code
    | ROUTER_ADVERTISEMENT -> int_to_router_advertisement_code
    | ROUTER_SOLICITATION -> int_to_default_code
    | TIME_EXCEEDED -> int_to_time_exceeded_code
    | BAD_IP_HEADER -> int_to_bad_ip_header_code
    | TIMESTAMP -> int_to_default_code 
    | TIMESTAMP_REPLY -> int_to_default_code



  let int_to_code ty code =
    match ty with
    | ECHO_REPLY ->
        (match int_to_default_code code with
        | Some c -> Some (ECHO_REPLY_CODE c)
        | None -> None)
    | DESTINATION_UNREACHABLE ->
        (match int_to_destination_unreachable_code code with
        | Some c -> Some (DESTINATION_UNREACHABLE_CODE c)
        | None -> None)
    | SOURCE_QUENCH ->
        (match int_to_destination_unreachable_code code with
        | Some c -> Some (DESTINATION_UNREACHABLE_CODE c)
        | None -> None)
    | REDIRECT_MESSAGE ->
        (match int_to_redirect_message_code code with
        | Some c -> Some (REDIRECT_MESSAGE_CODE c)
        | None -> None)
    | ECHO_REQUEST ->
        (match int_to_default_code code with
        | Some c -> Some (ECHO_REQUEST_CODE c)
        | None -> None)
    | ROUTER_ADVERTISEMENT ->
        (match int_to_router_advertisement_code code with
        | Some c -> Some (ROUTER_ADVERTISEMENT_CODE c)
        | None -> None)
    | ROUTER_SOLICITATION ->
        (match int_to_default_code code with
        | Some c -> Some (ROUTER_SOLICITATION_CODE c)
        | None -> None)
    | TIME_EXCEEDED ->
        (match int_to_time_exceeded_code code with
        | Some c -> Some (TIME_EXCEEDED_CODE c)
        | None -> None)
    | BAD_IP_HEADER ->
        (match int_to_bad_ip_header_code code with
        | Some c -> Some (BAD_IP_HEADER_CODE c)
        | None -> None)
    | TIMESTAMP ->
        (match int_to_default_code code with
        | Some c -> Some (TIMESTAMP_CODE c)
        | None -> None)
    | TIMESTAMP_REPLY ->
        (match int_to_default_code code with
        | Some c -> Some (TIMESTAMP_REPLY_CODE c)
        | None -> None)


  type icmpv4_packet =
    {
    ty: ty;
    code: code;
    length: int;
    next_protocol: Protocols.next_protocol;
    }

  let parse_packet v =
    Option.(
    int_to_ty (get_header_ty v) >>= fun ty ->
    int_to_code ty (get_header_code v) >>= fun code ->
    (* TODO: Checksum calculation *)
    let size = sizeof_ty ty v in
    let next_protocol = next_protocol ty code v in
     return ({ty=ty;
              code=code;
              length=size;
              next_protocol=next_protocol})
    )

  let get_payload ty v =
    Cstruct.shift v (sizeof_ty ty v)
end
