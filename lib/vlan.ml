module Ethernet_packet = struct
  [%%cstruct
  type vlan = {
      tci: uint16_t;
      tpid: uint16_t;
    } [@@big_endian]
  ]

end

