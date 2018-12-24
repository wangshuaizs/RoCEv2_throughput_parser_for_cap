# coding=gbk
from __future__ import print_function

import dpkt
import os

file_path = r'./capfile/test.cap'
sip_list =["*", "192.168.79.54", "192.168.79.54", "192.168.79.54", "192.168.79.54"]
dip_list =["*", "192.168.79.55", "192.168.79.56", "192.168.79.57", "192.168.79.58"]
interval = 0.001 # unit : second
if len(sip_list) != len(dip_list):
    print("the length of source ip must be equal to that of destination ip!")
    exit(-1)
ip_ascii_list = []
for i in range(len(sip_list)):
    sip_str = sip_list[i]
    dip_str = dip_list[i]
    if sip_str != "*":
        # from Dotted Decimal Notation to ascii
        sip_ascii = ''.join(map(chr, map(int, sip_str.split("."))))
        # from ascii to Dotted Decimal Notation
        # sip_str = '%d.%d.%d.%d' % tuple(map(ord,list(sip_ascii)))
    else:
        sip_ascii = ""
    if dip_str != "*":
        dip_ascii = ''.join(map(chr, map(int, dip_str.split("."))))
    else:
        dip_ascii = ""
    ip_ascii_list.append(sip_ascii+">"+dip_ascii)

throughput = {}
bytes_count = {}
for i in range(len(ip_ascii_list)):
    throughput[ip_ascii_list[i]] = []
    bytes_count[ip_ascii_list[i]] = 0

reference_time = 0
interval_count = 1

with open("new_throughput.txt", 'w') as f:
    print("Interval start", end="", file=f)
    for i in range(len(ip_ascii_list)):
        print(",%s" %(sip_list[i]+">"+dip_list[i]), end="", file=f)
    print("", file=f)

    with open(file_path , 'rb') as file_cap:
        string_data = dpkt.pcap.Reader(file_cap)

        pkt_num = 0
        for ts, Pkt in string_data:   
            reference_time = ts
            break

        for ts, Pkt in string_data:
            if pkt_num % 100000 == 0:
                print("%d packets have been processed..." % pkt_num)
            pkt_num += 1
            if (ts - reference_time) >= (interval * interval_count):
                interval_count += 1
                print("%f" % (interval*(interval_count-2)), end="", file=f)                                  
                for i in range(len(ip_ascii_list)):
                    key = ip_ascii_list[i]
                    throughput[key].append(float(bytes_count[key]*8)/float(interval)/float(1000000000)) # Gbps
                    bytes_count[key] = 0
                    print(",%f" % (throughput[ip_ascii_list[i]][interval_count-2]), end="", file=f)
                print("", file=f)

            try:
                eth = dpkt.ethernet.Ethernet(Pkt)
                vlan = dpkt.ethernet.VLANtag8021Q(Pkt)
                if eth.type == 0x8100 and eth.vlan_tags[0].type == 0x0800: # type: vlan + ip
                    ip = eth.data           
                    if ip.p == 17:
                        udp = ip.data
                        if udp.dport == 4791:
                            # both src and dst
                            key = ip.src + ">" + ip.dst
                            if key in ip_ascii_list:
                                bytes_count[key] = bytes_count[key] + ip.len + 22 # 22: bytes including vlan
                                #src_dst = {'src':'%d.%d.%d.%d'%tuple(map(ord,list(ip.src))),'dst':'%d.%d.%d.%d'%tuple(map(ord,list(ip.dst)))}
                                #print(src_dst)

                            # only src
                            key = ip.src + ">" + ""
                            if key in ip_ascii_list:
                                bytes_count[key] = bytes_count[key] + ip.len + 22

                            # only dst
                            key = "" + ">" + ip.dst
                            if key in ip_ascii_list:
                                bytes_count[key] = bytes_count[key] + ip.len + 22

                            # neither src nor dst
                            key = "" + ">" + ""
                            if key in ip_ascii_list:
                                bytes_count[key] = bytes_count[key] + ip.len + 22
            except:
                continue
    
    print("finish parsing!")
    file_cap.flush()
    print("Done")
