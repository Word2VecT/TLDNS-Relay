# TLDNS Relay

## System Function Design

### Basic Tasks

Design a DNS relay server program that reads a "Domain Name - IP Address" mapping table. When a client queries the IP address corresponding to a domain name, the domain name is searched in the table, resulting in three possible outcomes:

- If the result is an IP address `0.0.0.0`, return an error message "Domain name does not exist" to the client instead of returning the IP address `0.0.0.0`, implementing a malicious website blocking function.
- If the result is a regular IP address, return this address to the client, implementing DNS server functionality.
- If the domain name is not found in the table, send the query to an Internet DNS server and return the result to the client, implementing DNS relay functionality.

The implementation must adhere to the DNS protocol specifications to ensure interoperability with Windows and other systems.

Notes:

1. **Concurrent Clients**: Allow concurrent queries from multiple clients (which may be on different computers). This means processing another client's query request even if the first query has not been answered yet (the role of the ID field in the DNS protocol header), requiring message ID translation.
2. **Timeout Handling**: Consider the unreliability of UDP, and handle situations where the external DNS server (relay) does not respond or responds late.

### Additional Functions

- Implement LRU mechanism for Cache.
- Optimize the dictionary lookup algorithm.
- Ensure consistent performance across Windows/Linux source code.

### Extra Features

- Support for IPv6.
- Cross-platform support for Windows/Linux/MacOS.
- Implement high-performance querying using an event-driven, non-blocking asynchronous I/O model.
- Implement query pools and index pools to support concurrent queries.
- Support multiple message types, including A, CNAME, SOA, MX, and AAAA.
- Provide command-line argument parsing and help documentation.

## Quick Start

### Quick Start

1. Clone the repository locally and navigate into it:
    ```bash
    git clone https://github.com/Word2VecT/TLDNS-Relay.git
    cd TLDNS-Relay
    ```
2. Download and install [libuv](https://dist.libuv.org/dist/).
3. Import the project folder in CLion, compile, and run.
4. Set your DNS to `127.0.0.1`.
5. Enjoy!

### Program Help

Use the `-h` parameter to view the program help documentation.
```c
Usage:
[-a] Use the specified name server
[-d] Debug level mask, a 4-bit binary number, DEBUG, INFO, ERROR, FATAL in order
[-f] Use the specified DNS hosts file
[-l] Log information storage location
[-p] Custom listening ports
[-h] Helpful Information

Example:
-d 1111 -a 192.168.0.1 -f c:\dns-table.txt
Output all debugging information
Use the specified name server 192.168.0.1
Use the specified configuration file c:\dns-table.txt

-d 1101 -l /Users/Code -p 53
Output DEBUG, INFO, and FATAL information
Output debugging information to /Users/Code as a file
```

## Reference

- [Domain names - concepts and facilities](https://www.rfc-editor.org/info/rfc1034). RFC 1034, RFC Editor, November 1987, DOI: 10.17487/RFC1034. 55 pages. Abstract: This RFC is the revised basic definition of The Domain Name System. It obsoletes RFC-882. This memo describes the domain style names and their use for host address look up and electronic mail forwarding. It discusses the clients and servers in the domain name system and the protocol used between them.

- [Domain names - implementation and specification](https://www.rfc-editor.org/info/rfc1035). RFC 1035, RFC Editor, November 1987, DOI: 10.17487/RFC1035. 55 pages. Abstract: This RFC is the revised specification of the protocol and format used in the implementation of the Domain Name System. It obsoletes RFC-883. This memo documents the details of the domain name client-server communication.

- Stroustrup, Bjarne. *The C++ Programming Language*. Pearson Education, 2013.

- Wikipedia. [红黑树 --- Wikipedia, The Free Encyclopedia](http://zh.wikipedia.org/w/index.php?title=%E7%BA%A2%E9%BB%91%E6%A0%91&oldid=81848547). [Online; accessed 01-July-2024].