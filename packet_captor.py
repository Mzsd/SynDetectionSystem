import time
import json
import psutil
import pyshark
import numpy as np
import pandas as pd

from keras.models import model_from_json, load_model
from sklearn.preprocessing import StandardScaler


class DosIdentifier():

    def __init__(self):
        self.model = self.get_model()
        self.model.load_weights("brnn_weights.h5")
        self.main_ip = "192.168.8.103"
        self.ip_dicts = dict()
        self.first = list()

    def get_model(self):
        # with open("brnn_model.json") as js:
        #     model = model_from_json(js.read(), custom_objects={}) 
        return load_model('brnn_model.h5')

    # Helper Functions
    def get_packet_value(self, packet, layer, field):
        if hasattr(packet, layer):
            return str(getattr(packet, layer)._all_fields[f'{layer}.{field}'])
        return 0

    def is_malicious(self, X):
        predict = self.model.predict(X, verbose=1)

        predictn = predict.flatten().round()
        predictn = predictn.tolist()
        print(predictn)
        malicious_count = 0

        for y in predictn:
            if y == 1:
                malicious_count += 1
            
        malicious_percent = (malicious_count / len(predictn)) * 100

        return malicious_percent, True if malicious_percent > 50 else False

    def prepare_for_model(self, ip_dict):
        df = pd.DataFrame(ip_dict)
        df = df.drop(['ip.src', 'ip.dst', 'frame.protocols'], axis=1)
        # print(df)
        features = list(df.columns)

        X = np.array(df[features].values)
        # print(X)
        # Applying standard scaler to normalize the data
        scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
        scalar.fit(X)
        X = scalar.transform(X)
        X = np.asarray(X).astype(np.float32)
        # print(X.shape)
        X = X.reshape((1, X.shape[0], X.shape[1]))
        # print(X.shape)
        # Applying Feature transformation
        # features = len(X[0]) # <- 25
        # samples = X.shape[0] # <- 1000
        
        return X
        # print(samples)
        
        # test_len = 25
        # input_len = samples - test_len # for eg: <- 975
        # I = np.zeros((input_len, test_len, features)) # for eg:  np.zeros((25, 25, 25))

        # for i in range(input_len):
        #     temp = np.zeros((test_len, features))
        #     for j in range(i, i + test_len - 1):
        #         temp[j-i] = X[j]
        #     I[i] = temp
        
        # return I

    def split_data_in_ips(self, packet):
        
        ip = packet['ip.dst'][0] if self.main_ip == packet['ip.src'][0] else packet['ip.src'][0]
        
        if ip not in self.ip_dicts:
            self.ip_dicts[ip] = packet
        else:
            for col in self.ip_dicts[ip]:
                self.ip_dicts[ip][col] += packet[col]
                if len(self.ip_dicts[ip][col]) > 25:
                    self.ip_dicts[ip][col].pop(0)

    def packet_to_dict(self, packet):

        columns = [ "frame.len", "frame.protocols", "ip.hdr_len", "ip.len",
                    "ip.flags.rb", "ip.flags.df", "p.flags.mf", "ip.frag_offset", "ip.ttl",
                    "ip.proto", "ip.src","ip.dst", "tcp.srcport", "tcp.dstport", "tcp.len",
                    "tcp.ack", "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn",
                    "tcp.flags.urg", "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
                    "tcp.flags.syn", "tcp.flags.fin", "tcp.window_size", "tcp.time_delta"]

        packets_dict =  { 
                            col:    [   str(packet.frame_info._all_fields[col]) 
                                        if col.split('.')[0] == 'frame'
                                        else 
                                        self.get_packet_value(  packet, 
                                                                col.split('.')[0], 
                                                                '.'.join(col.split('.')[1:]))]

                            for col in columns
                        }

        return packets_dict

    def listen_on_interface(self, interface):
        """
        :param interface: The name of the interface on which to capture traffic
        :return: generator containing live packets
        """
        # print(interface)
        display_filter = f"ip.addr == {self.main_ip} && tcp.port == 8000"
        # print(display_filter)
        capture = pyshark.LiveCapture(  interface=interface,
                                        display_filter=display_filter)
        # capture.set_debug()
        for item in capture.sniff_continuously():
            yield item
            
def main():

    di = DosIdentifier()
    addrs = psutil.net_if_addrs()
    interfaces = [addr for addr in addrs.keys() if 'Loopback' not in addr]
    
    for packet in di.listen_on_interface(interfaces):
        
        packet_dict = di.packet_to_dict(packet)
        di.split_data_in_ips(packet_dict)
        
        for ip in di.ip_dicts:
            # print(ip, di.ip_dicts[ip][list(di.ip_dicts[ip].keys())[0]], '\n', di.ip_dicts[ip], '\n')
            if len(di.ip_dicts[ip][list(di.ip_dicts[ip].keys())[0]]) >= 25:
                # print(ip, len(di.ip_dicts[ip][list(di.ip_dicts[ip].keys())[0]]))
                X = di.prepare_for_model(di.ip_dicts[ip])
                malicious_percent, malicious = di.is_malicious(X)
                print(  "IP:", ip, 
                        'Percent:', str(malicious_percent) + '%', 
                        'Malicious:', malicious)
                di.ip_dicts[ip]

        # di.split_data_in_ips(packets_dict)

        # for ip, df in zip(self.ips, self.dfs)
        #     if len(df) >= 100:
        #         X = di.prepare_for_model(df)
        #         malicious_percent, malicious = di.is_malicious(X)

        #         ### IF ip is malicious
        #         ### Block that IP
        #         
        

if __name__ == '__main__':
    main()