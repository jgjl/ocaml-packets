`ocaml-packets` provides low-level network packet parsing and processing.
It is based on the `Wire_structs` module from the `mirage-tpcip` project.
The goal of this library is to move the low-level packet parsing and processing
of `mirage-tcpip` into its own library.

### License

`ocaml-packets` is distributed under the ISC license.

### Packet format description API

Two recent papers on packet format description  where identified:
 - P4: Bosshart, Pat, et al. "P4: Programming protocol-independent packet processors." ACM SIGCOMM Computer Communication Review 44.3 (2014): 87-95.
 - Nail: Bangert, Julian, and Nickolai Zeldovich. "Nail: A practical tool for parsing and generating data formats." 11th USENIX Symposium on Operating Systems Design and Implementation (OSDI 14). 2014.

P4 focusses on packet processing in general and gives less attention to packet parsing. However, the generic approach of P4 enables the handling of complex packet formats as well. An example for parsing TLV fields in given in [1].

Nail aims solely at providing an API/DSL for describing packet formats. The examples include complex packet formats such as dns, including optional fields, variable number of fields and field deconding/encoding [2].

Nail seems more promising, let's see if this approach can be build with Ocaml and ppx.

New idea: why not use Yang [3]? It is widely used in networking, tools are available [4], and seems to be capable to express all required packet characteristics.

More yang links:

 - http://www.ietf.org/edu/technical-tutorials.html#netconfandyang
 
Another approach is Katai, a system to develop parsers for binary structures:

 - http://kaitai.io/

Code references:

[1] https://github.com/p4lang/tutorials/blob/master/examples/TLV_parsing/p4src/TLV_parsing.p4

[2] https://github.com/jbangert/nail/blob/master/examples/dns/dns.nail

[3] http://yang-central.org/twiki/bin/view/Main/InetTypesHtml

[4] https://github.com/mbj4668/pyang
