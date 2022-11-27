import sys
import json
import psutil

import socket
import pyshark
import keyboard
import numpy as np
import pandas as pd



class DataSetCreator():
    
    columns = [ "frame.len", "frame.protocols", "ip.hdr_len", "ip.len",
            "ip.flags.rb", "ip.flags.df", "p.flags.mf", "ip.frag_offset", "ip.ttl",
            "ip.proto", "ip.src","ip.dst", "tcp.srcport", "tcp.dstport", "tcp.len",
            "tcp.ack", "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn",
            "tcp.flags.urg", "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
            "tcp.flags.syn", "tcp.flags.fin", "tcp.window_size", "tcp.time_delta"]
    
    def __init__(self):
        self.packet_dict =  {
                                col: []
                                for col in self.columns
                            }
    
    # Helper Functions
    def get_packet_value(self, packet, layer, field):
        if hasattr(packet, layer):
            return str(getattr(packet, layer)._all_fields[f'{layer}.{field}'])
        return 0

    def packet_to_dict(self, packet):

        packets =   {
                        col:    [   str(packet.frame_info._all_fields[col]) 
                                    if col.split('.')[0] == 'frame'
                                    else 
                                    self.get_packet_value(  packet, 
                                                            col.split('.')[0], 
                                                            '.'.join(col.split('.')[1:]))]

                        for col in self.columns
                    }

        if len(self.packet_dict[self.columns[0]]):
            for col in packets:
                self.packet_dict[col] += packets[col]
        else:
            self.packet_dict = packets
            
        print(len(self.packet_dict['frame.len']))

    def listen_on_interface(self, main_ip, interface):
        """
        :param interface: The name of the interface on which to capture traffic
        :return: generator containing live packets
        """
        # print(interface)
        display_filter = f"ip.addr == {main_ip} && tcp.port == 8000"
        # print(display_filter)
        capture = pyshark.LiveCapture(  interface=interface,
                                        display_filter=display_filter)
        # capture.set_debug()
        for item in capture.sniff_continuously():
            yield item


def main():
    
    if len(sys.argv) < 2:
        print('[-] Define Y')
        sys.exit()
    
    ds = DataSetCreator()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    main_ip = s.getsockname()[0]
    print(main_ip)
    s.close()

    addrs = psutil.net_if_addrs()
    interfaces = [addr for addr in addrs.keys() if 'Loopback' not in addr]
    
    for packet in ds.listen_on_interface(main_ip, interfaces):
        ds.packet_to_dict(packet)
        
        if len(ds.packet_dict[ds.columns[0]]) > 10000:
            break

    df = pd.DataFrame(ds.packet_dict)
    
    df['Y'] = sys.argv[1]
    
    print(df)

    df.to_csv('Dataset.csv', index=None)
    
    
if __name__ == '__main__':
    main()
    