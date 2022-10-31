# Naseeba Faiza
# CSE310 Networks Programming Assignment 2
import socket
from collections import Counter
import dpkt

class Packet():
	def __init__(self, pkt_inp):
		self.timestamp = pkt_inp[0]
		self.raw_data = pkt_inp[1]
		pkt_raw = pkt_inp[1]
		self.ether_dst = pkt_raw[:6]
		self.ether_src = pkt_raw[6:12]
		self.ether_type = pkt_raw[12:14]
		self.ip_len = int.from_bytes(pkt_raw[16:18], byteorder='big')
		self.ip_src = pkt_raw[26:30]
		self.ip_dst = pkt_raw[30:34]
		self.tcp_srcport = int.from_bytes(pkt_raw[34:36], byteorder='big')
		self.tcp_destport = int.from_bytes(pkt_raw[36:38], byteorder='big')
		self.tcp_seqnum	= int.from_bytes(pkt_raw[38:42], byteorder='big')
		self.tcp_acknum = int.from_bytes(pkt_raw[42:46], byteorder='big')

		self.tcp_header_len	= 4*(int.from_bytes(pkt_raw[46:47], byteorder='big')>>4)
		self.all_flags = int.from_bytes(pkt_raw[47:48], byteorder='big')
		self.mss = int.from_bytes(pkt_raw[56:58], byteorder='big')

		self.tcp_flag_fin = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.syn = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_rst = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_psh = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.ack = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_urg = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_ecn = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_cwr = self.all_flags&1
		self.all_flags = self.all_flags>>1
		self.tcp_flag_non = self.all_flags&1
		
		self.tcp_payload = pkt_raw[34+self.tcp_header_len:]
		self.tcp_payload_len = len(self.tcp_payload)
		self.receive_win = int.from_bytes(pkt_raw[48:50], byteorder='big')

	def __str__(self):
		return "Timestamp : " + str(self.timestamp)\
				 +"\tSource port: " + str(self.tcp_srcport)\
				 +"\tDest port  : " + str(self.tcp_destport)\
				 +"\tTCP SQ num : " + str(self.tcp_seqnum)\
				 +"\tTCP ACK num: " + str(self.tcp_acknum)\
				 +"\tTCP len: " + str(self.tcp_payload_len)\
				 +"\tRec Win: " + str(self.receive_win)\
				 +"\t[SYN]"*self.syn\
				 +"\t[ACK]"*self.ack

class Flow():
	def __init__(self, syn_pkt):
		self.eth_dst = syn_pkt.ether_dst
		self.eth_src = syn_pkt.ether_src
		self.ip_1 = syn_pkt.ip_src
		self.ip_2 = syn_pkt.ip_dst
		self.port_1 = syn_pkt.tcp_srcport 
		self.port_2 = syn_pkt.tcp_destport
		self.packets = []

	def get_packets(self,list_pkts):
		for pkt in list_pkts:
			if ((pkt.tcp_srcport == self.port_1 and pkt.tcp_destport == self.port_2)
				or (pkt.tcp_srcport == self.port_2 and pkt.tcp_destport == self.port_1)):
				self.packets.append(pkt)

	def __str__(self):
		return "\n".join([str(x) for x in self.packets])

	def get_resp(self,pkt):
		srcport = pkt.tcp_destport
		exp_ack_num = pkt.tcp_seqnum + pkt.tcp_payload_len
		for pkt in self.packets:
			if (pkt.tcp_srcport == srcport and pkt.tcp_acknum == exp_ack_num and not pkt.syn):
				return pkt


	def get_throughput(self,ip):
		destip = socket.inet_aton(ip)
		lengths = {}
		start_time = None
		end_time = None
		for pkt in self.packets:
			if (pkt.ip_dst == destip and (not pkt.syn) and (not pkt.tcp_flag_fin)):
				lengths[pkt.tcp_seqnum] = pkt.tcp_payload_len
				if start_time == None:
					start_time = pkt.timestamp
				end_time = pkt.timestamp

		data_total = sum(lengths.values())*9
		time_total = (end_time - start_time)

		return (data_total/time_total)/1000000

	def get_loss_data(self):
		seq_all = []
		for pkt in self.packets:
			if (pkt.tcp_destport==80 and (not pkt.syn)
				and (not pkt.tcp_flag_fin) and pkt.tcp_payload_len>0):
				seq_all.append(pkt.tcp_seqnum)
		total = len(seq_all)
		unique = len(set(seq_all))

		return total-unique,total

	def get_avg_rtt(self):
		data_pkts = {}
		for pkt in self.packets:
			if (not pkt.syn) and (not pkt.tcp_flag_fin):
				if (pkt.tcp_destport==80 and pkt.tcp_payload_len>0):
					data_pkts[pkt.tcp_seqnum] = pkt

		all_seqnum = list(data_pkts.keys())
		cntr = Counter(all_seqnum)
		non_repeat_seqnum = [val for val in cntr.keys() if cntr[val]==1]
		good_data_pkts = [data_pkts[seqnum] for seqnum in non_repeat_seqnum]

		rtt_list = []
		for data_pkt in good_data_pkts:
			ack_pkt = self.get_resp(data_pkt)
			if ack_pkt == None:
				continue
			timetaken = ack_pkt.timestamp - data_pkt.timestamp
			rtt_list.append(timetaken)
		return sum(rtt_list)/len(rtt_list)

	def get_cwnd_list(self):
		all_cwnd = []
		last_data = None
		for pkt_index in range(len(self.packets)):
			pkt = self.packets[pkt_index]
			if (not pkt.syn) and (not pkt.tcp_flag_fin):
				if pkt.tcp_destport==80:
					last_data = pkt
				if pkt.tcp_srcport==80 and pkt.ack:
					all_cwnd.append(last_data.tcp_seqnum - pkt.tcp_acknum + 1448)

		return(all_cwnd)

	def get_loss_char(self):
		data_seq = []
		ack_seq = []
		for pkt in self.packets:
			if (not pkt.syn) and (not pkt.tcp_flag_fin):
				if (pkt.tcp_destport==80 and pkt.tcp_payload_len>0):
					data_seq.append(pkt.tcp_seqnum)
				if pkt.tcp_srcport==80 and pkt.ack:
					ack_seq.append(pkt.tcp_acknum)

		ack_seq_counter = Counter(ack_seq)
		data_seq_freq = {seq_num:ack_seq_counter[seq_num] for seq_num in data_seq}
		triple_ack_count = len([seq for seq in data_seq_freq.keys() if data_seq_freq[seq]>2])

		total = len(data_seq)
		unique = len(set(data_seq))
		total_loss = total - unique

		return triple_ack_count, total_loss - triple_ack_count

def mss(packets):
	mss = 0
	for i in packets:
		if i.ack == 1 and i.syn == 1:
			mss = i.mss
	return mss

f = open("assignment2.pcap", "rb")
pcap_reader = dpkt.pcap.Reader(f)
pkt_bytes = pcap_reader.readpkts()
pkt_list = [Packet(x) for x in pkt_bytes]
mss_val = mss(pkt_list)

tcp_init_pkts = [x for x in pkt_list if (x.syn==1 and x.ack==0)]


print("\n1\n ")
print("Number of flows: ", len(tcp_init_pkts))
