(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(** One's complement checksum, RFC1071 *)
external ones_complement: Cstruct.t -> int = "caml_tcpip_ones_complement_checksum"

external ones_complement_list: Cstruct.t list -> int = "caml_tcpip_ones_complement_checksum_list"

let inet_csum field_list csum_field =
  (* 
   * Implement Internet checksum: RFC 1071, RFC1624
   * https://tools.ietf.org/html/rfc1624 
   * *)
  0

let inet_csum_packet fields_names result_field packet =
  (* 
   * Read from an write to packet
   * *)
  0

let checksum =
  let pbuf = Io_page.to_cstruct (Io_page.get 1) in
  let pbuf = Cstruct.set_len pbuf 4 in
  Cstruct.set_uint8 pbuf 0 0;
  fun packet bufs ->
    Cstruct.set_uint8 pbuf 1 (Ipv4_packet.get_ipv4_proto packet);
    Cstruct.BE.set_uint16 pbuf 2 (Cstruct.lenv bufs);
    let src_dst = Cstruct.sub packet 12 (2 * 4) in
    Tcpip_checksum.ones_complement_list (src_dst :: pbuf :: bufs)
