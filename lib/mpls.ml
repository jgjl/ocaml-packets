
module Mpls_packet = struct
  [%%cstruct
  type mpls = {
      label_upper: uint16_t;
      label_lower_tc_bos: uint8_t;
      ttl: uint8_t;
    } [@@big_endian]
  ]

  exception ParseError of string
  
  let tag_mask_and = Int32.of_int 0xfff00000
  let tag_mask_or =  Int32.neg tag_mask_and 

  let tc_mask_or = 0b1110
  let tc_mask_and = ~- tc_mask_or

  let bos_mask_or = 0b1
  let bos_mask_and = ~- bos_mask_or

  let get_label buf = Int32.to_int(Cstruct.BE.get_uint32 buf 0) lsr 4
  let get_tc buf = ((Cstruct.get_uint8 buf 2) lsr 1) land 0x7
  let get_s buf = (Cstruct.get_uint8 buf 2) land 0x1

  let set_label buf label = 
    let int32_label = Int32.of_int label in
    let checked_label = if ((int32_label <= tag_mask_or) && (int32_label >= Int32.zero)) 
                        then int32_label
                        else raise (ParseError "MPLS Label not in valid range.") in
    Cstruct.BE.set_uint32 buf 0 Int32.(logor (logand (Cstruct.BE.get_uint32 buf 0) tag_mask_and) checked_label)
  let set_tc buf tc = 
    let checked_tc = if ((tc <= tc_mask_or) && (tc >= 0)) 
                        then tc
                        else raise (ParseError "TC value not in valid range.") in
    Cstruct.set_uint8 buf 2 (((Cstruct.get_uint8 buf 2) land tc_mask_or) lor checked_tc)
  let set_s buf bos = 
    let checked_bos = if ((bos <= bos_mask_or) && (bos >= 0)) 
                        then bos 
                        else raise (ParseError "BOS value not in valid range.") in
    Cstruct.set_uint8 buf 2 ((Cstruct.get_uint8 buf 2) lor checked_bos)
end

