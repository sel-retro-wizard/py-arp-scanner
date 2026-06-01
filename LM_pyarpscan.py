# ARP Scanner
# Input - IPv4 Subnet
# Output - ARP Table of connected devices
# Modules - socket, uuid, ipaddress, struct, argparse
import socket
import uuid
import ipaddress
from struct import pack
import argparse

# CLI management via argparse
# Get user input from CLI
cli = argparse.ArgumentParser(description="Simple ARP Scanner. Takes an IPv4 subnet as input and outputs all avaliable devices on that network.")

# User Input
cli.add_argument("network_address", type=str, help="An IPv4 Network Address. Expressd as 192.168.1.0/24, 192.168.1.0/255.255.255.0 or 192.168.1.0/0.0.0.255")

# Read argument
args = cli.parse_args()

# ----------------------------------------

# Build network object - Used for subnet range
try:
    # Use subnet provided by user
    subnet = ipaddress.IPv4Network(args.network_address, strict=True)
except Exception as e:
    # If input is not a valid subenet
    print(f"{e}\nThe network address must be entered in any of the following formats:\n192.168.1.0/24, 192.168.1.0/255.255.255.0 or 192.168.1.0/0.0.0.255")
    exit()

# ----------------------------------------

# Create dummy packet to identify host IP address
try:
    # Open temporary socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Get IP address from current subnet
    ip = str(list(subnet.hosts())[0])
    # Attempt connection to subnet IP to generate packet
    sock.connect((ip, 80))
    # Get source IP from generated packet
    src_ip_str = sock.getsockname()[0]
    # Pack source_ip into bytes
    src_ip_bytes = ipaddress.IPv4Address(src_ip_str)
    # Close socket
    sock.close()
except:
    # Display error message if getting host IP address fails
    print(f"Unable to identify network. Please ensure machine is connected to correct network or network address was entered correctly")
    exit()

# Calculate total number of possible hosts, removing network id, broadcast and localhost from count
# Get total number
hosts = subnet.num_addresses
if hosts < 3:
    possible_hosts = 1
else:
    possible_hosts = hosts - 3

# ---------------------------------------

# Get host mac using UUID.
# String
src_mac_str = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
# Bytes
src_mac_bytes = bytes.fromhex(src_mac_str.replace(":", "")) 

# ---------------------------------------

# Initialize ARP array. A set of tuple(MAC, IP).
connected_devices = []

# ---------------------------------------

# Create ARP Frame, without target IP
# Set broadcast MAC address
dest_mac = b"\xff\xff\xff\xff\xff\xff"
# Set EtherType field - ARP
ether_type = pack("!H", 0x0806)
# Set Hardware Type - Ethernet
hard_type = pack("!H", 0x0001)
# Set Protocol Type - IPv4 Packet
proto_type = pack("!H", 0x0800)
# Set Hardware Size
hard_size = pack("!B", 0x06)
# Set Protocol Size 
proto_size = pack("!B", 0x04)
# Set Opcode - Request
opcode = pack("!H", 0x0001)
# Target MAC Address
tar_mac = (b"\x00"*6)

# Combine into almost complete packet
arp_packet = dest_mac + src_mac_bytes + ether_type + hard_type + proto_type + hard_size + proto_size + opcode + src_mac_bytes + src_ip_bytes.packed + tar_mac

# ---------------------------------------

#Show user host information and inform them of scan

print(f"Beginning ARP Scan of network: {subnet}")
print(f"===--------------------------------------------===")
print(f"Host Information:\nMAC: {src_mac_str} | IP: {src_ip_str}")
print(f"===--------------------------------------------===")
print(f"Scanning for {possible_hosts} potential host/s...")

# --------------------------------------

# Core part of the program.
# Create socket and bind to eth0 interface
try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("eth0",0x0806))
except:
    print("Unable to bind socket, needs elevated privleges")
    sock.close()
    exit()

# Start ARP Scan
try:
    # For each ip address in subnet
    # Temorary device list
    temp_devices = set()
    for addr in subnet:
        # Build ARP frame
        arp_request = arp_packet + addr.packed
        # Send ARP Request
        sock.send(arp_request)
        # Listen for response
        try:
            # Set timeout to half a second
            sock.settimeout(0.2)
            # Listen for reply
            reply = sock.recv(2048)
            # Get responders MAC Address
            resp_mac = ':'.join(f'{b:02x}' for b in reply[22:28])
            # Add to list of connected devices
            temp_devices.add(addr)        
        # If timeout, then move on to next IP
        except socket.timeout:
            pass
    print("Verifying...")
    # Verify found devices
    for addr in temp_devices:
        # Build ARP frame
        arp_request = arp_packet + addr.packed
        # Send ARP Request
        sock.send(arp_request)
        # Listen for response
        try:
            # Set timeout to half a second
            sock.settimeout(0.2)
            # Listen for reply
            reply = sock.recv(2048)
            # Get responders MAC Address
            resp_mac = ':'.join(f'{b:02x}' for b in reply[22:28])
            # Add to list of connected devices
            connected_devices.append((resp_mac, str(addr)))
        # If timeout, then move on to next IP
        except socket.timeout:
            pass


# For any errors
except Exception as e:
    print(f"Error: {e}")
    sock.close()
    exit()

# Close socket
sock.close()

# --------------------------------------

# Sort found devices by IP
connected_devices = sorted(connected_devices, key = lambda device: device[1])

# --------------------------------------

print(f"===--------------------------------------------===")
#Display results
if len(connected_devices) > 0:
    print("Hosts found:")
    #Loop through found devices
    for device in connected_devices:
        print(f"MAC: {device[0]} | IP: {device[1]}")
else:
    print(f"No hosts found")
print(f"===--------------------------------------------===")


