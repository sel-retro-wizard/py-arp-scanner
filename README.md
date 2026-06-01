# Python ARP Scanner
---

This script is an ARP scan tool made in python primarliy using the socket module. It was made as an educational exercise to learn how ARP packets and linux sockets work. 

The script takes an IP or subnet, sends out a batch of arp requests and listens for replies. It then sends out a second batch of all the initial replies to verify the MAC addresses. 
It does this because just running it once seems to catch incorrect IP/MAC pairs, I think because it's so slow, and it catches replies to the usual arp requests sent by the network stack.

This tool is very loud, and was only made and used for educational purposes. 
