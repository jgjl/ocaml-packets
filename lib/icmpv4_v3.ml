  

let protocol_no = Protocols.Internet (Stdint.Uint8.of_int 1)

[%%cenum
type destination_unreachable_code =
  | Destination_network_unreachable           [@id0]
  | Destination_host_unreachable              [@id2]
  | Destination_protocol_unreachable          [@id3]
  | Destination_port_unreachable              [@id4]
  | Fragmentation_required_and_DF_flag_set    [@id5]
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


type structure =
  | ECHO_REPLY of default_code
  | DESTINATION_UNREACHABLE of destination_unreachable_code
  | SOURCE_QUENCH of default_code
  | REDIRECT_MESSAGE of redirect_message_code
  | ECHO_REQUEST of default_code
  | ROUTER_ADVERTISEMENT of router_advertisement_code
  | ROUTER_SOLICITATION of default_code
  | TIME_EXCEEDED of time_exceeded_code
  | BAD_IP_HEADER of bad_ip_header_code
  | TIMESTAMP of default_code
  | TIMESTAMP_REPLY of default_code

module type Icmpv4_type = sig
  val ty : ty
  type code
  type field
  val get_field : field -> int
  val set_field : field -> int -> unit
  val sizeof : Cstruct.t -> int
  val get_next_protocol : Cstruct.t -> Protocols.next_protocol
end

module WireV2 = struct

  type t = Cstruct.t

  [%%cstruct
  type header = {
    ty:     uint8_t;
    code:   uint8_t;
    csum:   uint16_t;
  } [@@big_endian]
  ]

  module Echo = struct
    [%%cstruct
    type icmpv4 = {
      ty:     uint8_t;
      code:   uint8_t;
      csum:   uint16_t;
    } [@@big_endian]
    ]
  end

  module Destination_unreachable = struct
  end
    | Echo of [`identifier | `sequence_no]
    | Dst_unreach of [`next_hop_mtu]
    | Empty
    | Redir_msg of [`address]
    | Rtr_adv of [`addr_cnt|`addr_entry_size|`lifetime|`rtr_addr|`rtr_pref_lvl]
    | Bad_ip_hdr of [`pointer]
    | Timestamp of [`identifier|`sequence_no|`orig_ts|`rx_ts|`tx_ts]
  

  type fields =
    | Type
    | Code
    | Csum
    | Identifier
    | Sequence_no
    | Next_hop_mtu
    | Payload
    | Timestamp
    | Adv_cnt
    | Adv_entry_size
    | Lifetime
    | Router_address
    | Preference_lvl

  type ('a, 'b) icmpv4_type = {
    codes: int list;
    len: int;
    fields: 'a list;
    next_part: Protocols.next_protocol;
    get: 'a -> 'b;
    set: 'a -> 'b -> unit;
  }

  type types =
    | Echo of [`identifier | `sequence_no]
    | Dst_unreach of [`next_hop_mtu]
    | Empty
    | Redir_msg of [`address]
    | Rtr_adv of [`addr_cnt|`addr_entry_size|`lifetime|`rtr_addr|`rtr_pref_lvl]
    | Bad_ip_hdr of [`pointer]
    | Timestamp of [`identifier|`sequence_no|`orig_ts|`rx_ts|`tx_ts]

  let get ty =
    match ty with
    | ECHO_REPLY -> 
      (fun field v -> match field with
        | Echo `identifier -> Cstruct.BE.get_uint16 v 0
        | Echo `sequence_no -> Cstruct.BE.get_uint16 v 2)
    | DESTINATION_UNREACHABLE -> fun field v -> match field with
                      | Dst_unreach `next_hop_mtu -> Cstruct.BE.get_uint16 v 2

  let set ty =
    match ty with
    | ECHO_REPLY -> (fun field value -> function
                      | `identifier -> Cstruct.BE.set_uint16 value)

  let get_type ty =
    let identifier =    {offset=0; size=2; name="identifier"} in
    let sequence_no =   {offset=0; size=2; name="sequence number"} in
    let next_hop_mtu =  {offset=2; size=2; name="next hop mtu"} in
    let pointer =       {offset=0; size=1; name="pointer"} in
    let address =       {offset=0; size=2; name="sequence number"} in
    let orig_ts =       {offset=4; size=4; name="originate timestamp"} in
    let rx_ts =         {offset=8; size=4; name="receive timestamp"} in
    let tx_ts =         {offset=4; size=4; name="transmit timestamp"} in
    let ad_cnt =        {offset=0; size=1; name="advertisement count"} in
    let ad_entry_size = {offset=1; size=1; name="advertisement entry size"} in
    let lifetime =      {offset=2; size=2; name="lifetime"} in
    let rtr_addr =      {offset=4; size=4; name="router address"} in
    let rtr_pref_lvl =  {offset=8; size=4; name="preference level"} in
    let ipproto = Protocols.Protocol Ipv4.Ipv4_packet.protocol_no in
    match ty with
    | ECHO_REPLY -> {codes=[0]; len=4;
                    fields=[`identifier; `sequence_no;];
                    next_part=Protocols.Unknown;
                    get=(get ty);
                    set=(set ty);
                    }
    | DESTINATION_UNREACHABLE -> {name="Destination unreachable";
                    max_code=15; length=4;
                    fields=[next_hop_mtu];
                    next_part=ipproto}
    | SOURCE_QUENCH -> {name="Unused";
                    max_code=0; length=4;
                    fields=[];
                    next_part=ipproto}
    | REDIRECT_MESSAGE -> {name="Redirect message";
                    max_code=3; length=4;
                    fields=[address];
                    next_part=ipproto}
    | ECHO_REQUEST -> {name="Echo reply";
                    max_code=0; length=4;
                    fields=[identifier; sequence_no];
                    next_part=Protocols.Unknown}
    | ROUTER_ADVERTISEMENT -> {name="Router advertisement";
                    max_code=16; length=12;
                    fields=[ad_cnt; ad_entry_size; lifetime; rtr_addr; rtr_pref_lvl];
                    next_part=Protocols.None}
    | ROUTER_SOLICITATION -> {name="Router solicitation";
                    max_code=0; length=4;
                    fields=[];
                    next_part=Protocols.None}
    | TIME_EXCEEDED -> {name="Time exceeded";
                    max_code=1; length=4;
                    fields=[];
                    next_part=ipproto}
    | BAD_IP_HEADER -> {name="Bad IP header";
                    max_code=2; length=4;
                    fields=[pointer];
                    next_part=ipproto}
    | TIMESTAMP -> {name="Timestamp";
                    max_code=0; length=16;
                    fields=[identifier;sequence_no;orig_ts;rx_ts;tx_ts];
                    next_part=Protocols.None}
    | TIMESTAMP_REPLY -> {name="Timestamp reply";
                    max_code=0; length=16;
                    fields=[identifier;sequence_no;orig_ts;rx_ts;tx_ts];
                    next_part=Protocols.None}

  let get_payload ty_def v =
    let shiftlen = sizeof_icmpv4 + ty_def.length in
    if (Cstruct.len v) > shiftlen
    then Some (Cstruct.shift v shiftlen)
    else None

  let is_valid v ty code tys =
    let type_code_ok = ty <= ty && code <= tys.max_code
    in
    let length_ok = (sizeof_icmpv4 + tys.length) <= Cstruct.len v in
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
