#!/usr/bin/env python3

import sys
import struct
import socket


class IP_Header:  # reference from basic_structures.py
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def get_ip(self):
        return [self.src_ip,self.dst_ip]
    
    def get_header_len(self):
        return self.ip_header_len
    
    def get_total_len(self):
        return self.total_len   
        
    def set_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.src_ip = s_ip
        self.dst_ip = d_ip
        #print("s_ip",s_ip)
        #print("d_ip",d_ip)
        
    def set_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.ip_header_len = length
        #print("length",length)

    def set_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len = length
        #print("total",length)
 
class TCP_Header:  # reference from basic_structures.py
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def get_src_port(self):
        return self.src_port
        
    def get_dst_port(self):
        return self.dst_port
        
    def get_ports(self):
        return [self.src_port,self.dst_port]
        
    def get_seq_num(self):
        return self.seq_num
        
    def get_ack_num(self):
        return self.ack_num
        
    def get_data_offset(self):
        return self.data_offset
        
    def get_flags(self):
        return self.flags
    
    def get_win_size(self):
        return self.window_size
        
    def set_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port = port
        #print("src_port",self.src_port)
    
    def set_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port = port
        #print("dest_port",self.dst_port)
    
    def set_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num = seq
        #print("seq",seq)
    
    def set_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num = ack
        #print("ack",ack)
    
    def set_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
        #print(list(self.flags.items()))

    def set_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.window_size = size
        #print("win",size)
        
    def set_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset = length
        #print("data_offset",self.data_offset)
    
    def relative_seq_num(self):
        if(self.seq_num>=self.seq_orig_num) and ():
            relative_seq = self.seq_num - self.seq_orig_num
            self.set_seq_num(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self):
        if(self.ack_num>=self.ack_orig_num):
            relative_ack = self.ack_num-self.ack_orig_num+1
            self.set_ack_num(relative_ack)
   

class packet():  # reference from basic_structures.py
    
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.incl_len=0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_timestamp(self):
        return self.timestamp
        
    def get_incl_len(self):
        return self.incl_len
        
    def get_RTT_value(self,p):
        rtt = self.timestamp - p.timestamp     # why previous - current timestamp
        self.RTT_value = round(rtt,8)
        
    def set_from_where(self,first_packet):
        if (self.IP_header.get_ip()[0]) == (first_packet.IP_header.get_ip()[0]):
            self.from_where=0
        else:
            self.from_where=1

    def set_incl_len(self,buffer):
        self.incl_len=struct.unpack('I',buffer)[0]

class connection(): # a class storing each connection info

    def __init__(self):
        self.complete_flag=False
        self.src_addr=None
        self.dst_addr=None
        self.src_port=0
        self.dst_port=0
        self.status="S0F0"
        self.start=0
        self.end=0
        self.duration=0
        self.src_to_dst=0
        self.dst_to_src=0
        self.totalp=0
        self.byte_src_to_dst=0
        self.byte_dst_to_src=0
        self.total_byte=0
        self.total_win=[]
        self.packets=[]     # the packets number within this connectioon
        self.rtt=[]
    def get_addrs(self):
        return (self.src_addr,self.dst_addr)
    def get_ports(self):
        return (self.src_port,self.dst_port)
    def get_status(self):
        return self.status
    def get_times(self):
        return (self.start,self.end,self.duration)
    def get_sent_packets(self):
        return (self.src_to_dst,self.dst_to_src,self.totalp)
    def get_sent_bytes(self):
        return (self.byte_src_to_dst,self.byte_dst_to_src,self.total_byte)
    def get_total_win(self):
        return self.total_win
    def get_rtt(self):
        return self.rtt
    def set_addrs(self,addr):
        self.src_addr=addr[0]
        self.dst_addr=addr[1]
    def set_ports(self,ports):
        self.src_port=ports[0]
        self.dst_port=ports[1]
    def set_times(self,start,end):
        self.start=start
        self.end=end
        self.duration=self.end-self.start
    def set_packets_and_bytes_and_win(self,packet_list):
        for i in self.packets:
            self.total_win.append(packet_list[i].TCP_header.get_win_size())
            if packet_list[i].TCP_header.get_src_port()==self.src_port:
                self.byte_src_to_dst=self.byte_src_to_dst+packet_list[i].IP_header.get_total_len()-\
                (packet_list[i].IP_header.get_header_len()+packet_list[i].TCP_header.get_data_offset())
                self.src_to_dst+=1
            else:
                self.byte_dst_to_src=self.byte_dst_to_src+packet_list[i].IP_header.get_total_len()-\
                (packet_list[i].IP_header.get_header_len()+packet_list[i].TCP_header.get_data_offset())
                self.dst_to_src+=1
                
        self.total_byte=self.byte_src_to_dst+self.byte_dst_to_src
        self.totalp=len(self.packets)
        
    def set_complete_connections(self,packet_list):
        self.set_addrs(packet_list[self.packets[0]].IP_header.get_ip())
        self.set_ports(packet_list[self.packets[0]].TCP_header.get_ports())
        self.set_times(packet_list[self.packets[0]].get_timestamp(),packet_list[self.packets[-1]].get_timestamp())
        self.set_packets_and_bytes_and_win(packet_list)
    def set_incomplete_connections(self,packet_list):
        self.set_addrs(packet_list[self.packets[0]].IP_header.get_ip())
        self.set_ports(packet_list[self.packets[0]].TCP_header.get_ports())
        
    def add_packets(self,current):
        self.packets.append(current)
        
    def set_rtt(self,rtt):
        self.rtt.extend(rtt)
    

def global_header(header):  # read global header info
    big_endian='>'
    little_endian='<'
    global_info={"endianness":None,"thiszone":None,"smaplen":None,"orig_time":None}
    
    magic_num=header[0:4]

    if(magic_num==b'\xd4\xc3\xb2\xa1'):   # extract endianness
        endianness=little_endian
    else:
        endianness=big_endian

    global_info["endianness"]=endianness
    #global_info["thiszone"]=header[8:12]
    #global_info["smaplen"]=header[16:20]

    
    return global_info


def readfile(): # read cap file, extract info base on the byte order
    packet_list=[]
    nextpacket=16
    current_packet=-1

    if len(sys.argv)==2:
        try:
            file=open(sys.argv[1],"rb")
        except:
            print("File cannot open!!")
            exit(1)

    global_info=global_header(file.read(24))

    while(True):
        ph=file.read(nextpacket)  # packet header

        if not ph:
            break

        current_packet+=1
        packet_list.append(packet())
        packet_list[current_packet].packet_No_set(current_packet+1)

        if(current_packet==0):
            seconds = struct.unpack('I',ph[0:4])[0]
            microseconds = struct.unpack('<I',ph[4:8])[0]
            global_info["orig_time"] = round(seconds+microseconds*0.000001,6)
        else:
            packet_list[current_packet].timestamp_set(ph[0:4],ph[4:8],global_info["orig_time"])
        
        packet_list[current_packet].set_incl_len(ph[8:12])
        pd=file.read(packet_list[current_packet].get_incl_len())  # packet data incl_len

        # read IP info
        packet_list[current_packet].IP_header.set_IP(pd[26:30],pd[30:34])
        packet_list[current_packet].IP_header.set_header_len(pd[14:15])
        packet_list[current_packet].IP_header.set_total_len(pd[16:18])
        
        # read TCP info
        tcph=14+packet_list[current_packet].IP_header.get_header_len()
        packet_list[current_packet].TCP_header.set_src_port(pd[tcph:tcph+2])
        packet_list[current_packet].TCP_header.set_dst_port(pd[tcph+2:tcph+4])
        packet_list[current_packet].TCP_header.set_seq_num(pd[tcph+4:tcph+8])
        packet_list[current_packet].TCP_header.set_data_offset(pd[tcph+12:tcph+13])
        packet_list[current_packet].TCP_header.set_flags(pd[tcph+13:tcph+14]) #
        packet_list[current_packet].TCP_header.set_window_size(pd[tcph+14:tcph+15],pd[tcph+15:tcph+16])

        if packet_list[current_packet].TCP_header.get_flags()["ACK"]==1:
            packet_list[current_packet].TCP_header.set_ack_num(pd[tcph+8:tcph+12])

    file.close()
    return packet_list


def connection_detail(packet_list): # set each connection info
    
    connections=[]
    port_nums=[]  # use as the port numbers of the first packet in each connection
    addrs=[]
    rtt=[]
    current=-1  # use as index

    for i in range(len(packet_list)):  # matches each connection
        if (packet_list[i].TCP_header.get_flags()["SYN"]==1) and (packet_list[i].TCP_header.get_flags()["ACK"]==0):
            if current >= 0:
                if(packet_list[i].TCP_header.get_seq_num()==packet_list[connections[current].packets[0]].TCP_header.get_seq_num()) and\
                (packet_list[i].TCP_header.get_ack_num()==packet_list[connections[current].packets[0]].TCP_header.get_ack_num()):
                    continue
            connections.append(connection())
            current+=1
            connections[current].add_packets(i)
            connections[current].status=connections[current].status[0]+str(int(connections[current].status[1])+1)+connections[current].status[2:]
            port_nums=sorted(packet_list[i].TCP_header.get_ports())
            addrs=sorted(packet_list[i].IP_header.get_ip())
 
            for j in range(i+1,len(packet_list)):
                if (sorted(packet_list[j].TCP_header.get_ports())==port_nums) and (sorted(packet_list[j].IP_header.get_ip())==addrs):
                        
                    if (packet_list[j].TCP_header.get_flags()["SYN"]==1) and (packet_list[j].TCP_header.get_flags()["ACK"]==1):
                        connections[current].status=connections[current].status[0]+str(int(connections[current].status[1])+1)+connections[current].status[2:]
                    if (packet_list[j].TCP_header.get_flags()["RST"]==1 and ("/R" not in connections[current].status)): # mark as rst connection for current connection 
                        connections[current].status+="/R"
                    if packet_list[j].TCP_header.get_flags()["FIN"]==1:
                        connections[current].status=connections[current].status[0:3]+(str(int(connections[current].status[3])+1)+connections[current].status[4:])
                    
                    connections[current].add_packets(j)

    
    for i in connections:
        rtt_list=[]
        i.packets.sort()
        if (i.get_status()[1] != "0") and (i.get_status()[3] != "0"): # set complete & incomplete connections separately
            i.set_complete_connections(packet_list)
        else:
            i.set_incomplete_connections(packet_list)
            
        temp=i.packets[:]
        for j in range(0,len(temp)):    # calculate the rtt values
            if (packet_list[i.packets[j]].TCP_header.get_ports()[0]!=i.get_ports()[0]):
                continue
            cur_semt_len=packet_list[i.packets[j]].IP_header.get_total_len()-(packet_list[i.packets[j]].IP_header.get_header_len()+packet_list[i.packets[j]].TCP_header.get_data_offset())
            for k in range(j+1,len(temp)):
                if len(temp) <= 1:
                    break
                    
                if (packet_list[i.packets[k]].TCP_header.get_ack_num()==(packet_list[i.packets[j]].TCP_header.get_seq_num()+cur_semt_len)) and\
                (cur_semt_len>0):
                    rtt_list.append(packet_list[i.packets[k]].get_timestamp()-packet_list[i.packets[j]].get_timestamp())
                    temp.pop(k)
                    temp.pop(j)
                    break
              
                if(packet_list[i.packets[j]].TCP_header.get_flags()["SYN"]==1) and\
                (packet_list[i.packets[k]].TCP_header.get_ack_num()==(packet_list[i.packets[j]].TCP_header.get_seq_num()+1)):
                    rtt_list.append(packet_list[i.packets[k]].get_timestamp()-packet_list[i.packets[j]].get_timestamp())
                    temp.pop(k)
                    temp.pop(j)
                    break
                if (packet_list[i.packets[j]].TCP_header.get_flags()["FIN"]==1) and\
                (packet_list[i.packets[k]].TCP_header.get_ack_num()==(packet_list[i.packets[j]].TCP_header.get_seq_num()+1)):
                    rtt_list.append(packet_list[i.packets[k]].get_timestamp()-packet_list[i.packets[j]].get_timestamp())
                    temp.pop(k)
                    temp.pop(j)
                    break
                
                    
        i.set_rtt(rtt_list)
                
                
    return connections
    


def display(connections):
    total_rst=0
    still_open=0
    complete_TCP=[]
    duration_list=[]
    packets=[]
    win=[]
    rtt=[]
    
    print("A) Total number of connections:",len(connections))
    print()
    print(50*"-")
    print()
    print("B) Connections' details:")
    for i in range(0,len(connections)): # print all the connections
        print()
        print("Connection",i+1)
        print("Source address:",connections[i].get_addrs()[0])
        print("Destination address:",connections[i].get_addrs()[1])
        print("Source port:",connections[i].get_ports()[0])
        print("Destination port:",connections[i].get_ports()[1])
        print("Status:",connections[i].get_status())
        if "/R" in connections[i].get_status():    # count total rst
            total_rst+=1
        if connections[i].get_status()[3] == "0":
            still_open+=1
        if (connections[i].get_status()[1] != "0") and (connections[i].get_status()[3] != "0"):
            complete_TCP.append(i)
            print("Start time:",connections[i].get_times()[0],"seconds")
            print("End time:",connections[i].get_times()[1],"seconds")
            print("Duration:",round(connections[i].get_times()[2],6),"seconds")
            duration_list.append(connections[i].get_times()[2])
            print("Number of packets sent from source to destination:",connections[i].get_sent_packets()[0],"packets")
            print("Number of packets sent from destination to source:",connections[i].get_sent_packets()[1],"packets")
            print("Total number of packets:",connections[i].get_sent_packets()[2],"packets")
            packets.append(connections[i].get_sent_packets()[2])
            print("Number of data bytes sent from source to destination:",connections[i].get_sent_bytes()[0],"bytes")
            print("Number of data bytes sent from destination to source:",connections[i].get_sent_bytes()[1],"bytes")
            print("Total number of data bytes:",connections[i].get_sent_bytes()[2],"bytes")
            win.extend(connections[i].get_total_win())
            rtt.extend(connections[i].get_rtt())
            
        print(2*"\n")
    print("End")    
    print()
    print(50*"-")
    print()
    print("General")
    print("Total number of complete TCP connections:",len(complete_TCP))
    print("Number of reset TCP connections:",total_rst)
    print("Number of TCP connections that were still open when the trace capture ended:",still_open)
    print()
    print(50*"-")
    print()
    print("D) Complete TCP connections")
    print()
    print("Minimum time duration:",round(min(duration_list),6),"seconds")
    print("Mean time duration:",round((sum(duration_list)/len(duration_list)),6),"seconds")
    print("Maximum time duration:",round(max(duration_list),6),"seconds")
    print()
    print("Minimum RTT value:",round(min(rtt),6),"seconds")
    print("Mean RTT value:",round(sum(rtt)/len(rtt),6),"seconds")
    print("Maximum RTT value:",round(max(rtt),6),"seconds")
    print()
    print("Minimum number of packets including both send/received:",min(packets),"packets")
    print("Mean number of packets including both send/received:",round(sum(packets)/len(packets)),"packets")
    print("Maximum number of packets including both send/received:",max(packets),"packets")
    print()
    print("Minimum receive window size including both send/received:",min(win),"bytes")
    print("Mean receive window size including both send/received:",round(sum(win)/len(win),6),"bytes")
    print("Maximum receive window size including both send/received:",max(win),"bytes")


    
def main():
    packet_list=readfile()     # read cap file infomation
    
    connections=connection_detail(packet_list)  # extract each connection info
    
    display(connections)    # diaplay connection info


if __name__ == "__main__":
    main()
