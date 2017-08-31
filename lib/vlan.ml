module Ethernet_packet = struct
  [%%cstruct
  type vlan = {
      tci: uint16_t;
      tpid: uint16_t;
    } [@@big_endian]
  ]

  let get_vid buf = (get_vlan_tci buf) land 0b0000_1111_1111_1111
  let get_pcp buf = (get_vlan_tci buf) lsr 13
  let get_dei buf = ((get_vlan_tci buf) lsr 12) land 0b0001
end

