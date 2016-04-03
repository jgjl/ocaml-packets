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

P4 focusses on packet processing in general and gives less attention to packet parsing. The P4 source code is available on github. However, it does not seem to include "interesting" packet formats with options and variable length fields. In general, while the approach is interesting, its API/DSL is not convincing for out use case.

Nail aims solely at providing an API/DSL for describing packet formats. Furthermore, the examples include complex packet formats such as dns, including optional fields, variable number of fields and field deconding/encoding.

Nail seems more promising, let's see if this approach can be build with Ocaml and ppx.
