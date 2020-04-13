import struct
import socket


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    ipst = ''
    for i in range(0, len(raw_ip_addr)):
        byt = int.from_bytes(raw_ip_addr[i:i + 1], 'little')
        ipst += str(byt) + "."
    pass
    ipst = ipst[:-1]
    return ipst


def parse_application_layer_packet(ip_packet_payload: object) -> object:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    srcport = int.from_bytes(ip_packet_payload[0:2], 'big')
    destport = int.from_bytes(ip_packet_payload[2:4], 'big')
    offs = int.from_bytes(ip_packet_payload[12:14], 'big') & 15
    data = ip_packet_payload[24 + offs:]
    return TcpPacket(srcport, destport, offs, data)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    prot = ip_packet[9]
    IHL = ip_packet[0] & 15
    src, dest = struct.unpack('!4s 4s', ip_packet[12:20])
    pl = ip_packet[IHL * 4:]
    return IpPacket(prot, IHL, parse_raw_ip_addr(src), parse_raw_ip_addr(dest), pl)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    TCP=6
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,TCP)
    while True:
        # Receive packets and do processing here
        try:
            datapack, address = sock.recvfrom(4092)
            parse = parse_network_layer_packet(datapack)
            tcpparse = parse_application_layer_packet(parse.payload)
            if(tcpparse.payload.decode("UTF-8")):
                print(tcpparse.payload)
        except Exception:
            print("Not coded!")
    pass


if __name__ == "__main__":
    main()
