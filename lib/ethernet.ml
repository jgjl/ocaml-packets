module Ethernet_packet = struct
  [%%cstruct
  type ethernet = {
      dst: uint8_t        [@len 6];
      src: uint8_t        [@len 6];
      ethertype: uint16_t;
    } [@@big_endian]
  ]

  (*
  [%%cenum
  type ethertype =
    | ARP  [@id 0x0806]
    | IPv4 [@id 0x0800]
    | IPv6 [@id 0x86dd]
    [@@uint16_t]
  ]
  *)

  (*
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
      *)
end

