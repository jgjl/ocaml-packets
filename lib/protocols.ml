
type protocol =
  | EtherType of Stdint.uint16
  | Internet of Stdint.uint8

type next_protocol =
  | None
  | Unknown
  | Protocol_part
  | Protocol of protocol
