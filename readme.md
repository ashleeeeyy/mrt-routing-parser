# mrt-routing-parser
Quick little script to read MRT (RFC6396) BGP route dumps
and extract AS prefix announcements, and peering relationships

This script is a precursor to a RFC-compliant full parser

Data is then stored in a NoSQL database due to the relatively simple structure of the data
and the speed NoSQL database engines provide

local data is then compared with data in the database, and changes are to be made accordingly
- ex1: locally stored prefix 1.0.0.0/8 begins to be announced by cloudflare (AS13335), overwrite remote prefix entry
- ex2: remotely stored prefix 192.77.9.0/24 is no longer announced by anyone, remove it

## Sources
Routing data is automatically pulled from RIPE NCC's Routing and Information Services
(please be nice and don't download too much)

