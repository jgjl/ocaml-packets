
type protocol =
  | EtherType of Stdint.uint16
  | Internet of Stdint.uint8

type next_protocol =
  | None
  | Unknown
  | ProtocolOption
  | Protocol of protocol
