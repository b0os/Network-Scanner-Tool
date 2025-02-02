import time
import threading
from queue import Queue
import scapy.all as scapy
from datetime import datetime


def network_discovery(CIDR="/24"):
	def ping():
		ip_address = scapy.get_if_addr(scapy.conf.iface)
		broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_address + CIDR)
		return scapy.srp(broadcast, timeout=2, verbose=0)

	ip_addresses = []
	mac_addresses = []
	alive, dead = ping()
	for sent, received in alive:
		ip_addresses.append(received.psrc)
		mac_addresses.append(received.hwsrc)

	print(f"\n\n{'Active network devices:'}\n{'-' * 45}\n{'#':<5}{'IP Address':<20}{'MAC Address':<20}\n{'-' * 45}")
	for i in range(len(ip_addresses)):
		print(f"{i + 1:<5}{ip_addresses[i]:<20}{mac_addresses[i]:<20}")
	print("-" * 45)
	return ip_addresses, mac_addresses


def analyze_traffic(ip_addresses, COUNT=100):
	def capture(ip, protocol=""):
		pkts = scapy.sniff(filter=f"host {ip}", count=COUNT)
		pkts = filter_packets(pkts, protocol)
		analyze_packets(pkts)

	def analyze_packets(pkts: list):
		def display_packet_details(pkt, src_ip, dst_ip):
			if scapy.TCP in pkt:
				src_port = pkt[scapy.TCP].sport
				dst_port = pkt[scapy.TCP].dport
				print(f"TCP packet; from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

			elif scapy.UDP in pkt:
				src_port = pkt[scapy.UDP].sport
				dst_port = pkt[scapy.UDP].dport
				print(f"UDP packet; from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

			elif scapy.ICMP in pkt:
				icmp_type = pkt[scapy.ICMP].type
				print(f"ICMP packet; type {icmp_type} from {src_ip} -> {dst_ip}")

			else:
				print(f"IP packet; from {src_ip} -> {dst_ip}")

		for pkt in pkts:
			if scapy.IP in pkt:
				src_ip = pkt[scapy.IP].src
				dst_ip = pkt[scapy.IP].dst
				display_packet_details(pkt, src_ip, dst_ip)

	def filter_packets(pkts, protocol):
		if not pkts:
			print("No Packets to filter")
			return
		if protocol == "":
			return pkts
		filtered_pkts = []  # Clear previous filters
		for pkt in pkts:
			if protocol == "tcp" and scapy.TCP in pkt:
				filtered_pkts.append(pkt)
			elif protocol == "udp" and scapy.UDP in pkt:
				filtered_pkts.append(pkt)
			elif protocol == "icmp" and scapy.ICMP in pkt:
				filtered_pkts.append(pkt)
		return filtered_pkts

	print(f"{'Active devices detected:'}\n{'-' * 25}\n{'#':<5}{'IP Address':<20}\n{'-' * 25}")
	for i in range(len(ip_addresses)):
		print(f"{i + 1:<5}{ip_addresses[i]:<20}")
	print("-" * 25)
	key = int(input("Select a source ip address to sniff from (Enter source number): "))
	choice = int(input(
		"\n\t[1] ICMP Packets. \n\t[2] TCP Packets. \n\t[3] UDP Packets. \n\t[4] Without filtering. \nSelect packets type to filter or enter 0 to proceed without filtering (Enter option number): "))

	try:
		target = ip_addresses[key - 1]
		if (choice == 0):
			capture(target)
		elif (choice == 1):
			capture(target, protocol="icmp")
		elif (choice == 2):
			capture(target, protocol="tcp")
		elif (choice == 3):
			capture(target, protocol="udp")
		else:
			print("\nError, Invalid Input!")
	except Exception as e:
		print(f"Error: {e}")

	time.sleep(2)


def custom_packet(ip_addresses):

	def icmp(target):
		try:
			packet = scapy.IP(dst=target) / scapy.ICMP()
			return packet
		except Exception as e:
			return f"Error: {e}"

	def tcp(target, rcvport):
		try:
			packet = scapy.IP(dst=target) / scapy.TCP(dport=rcvport, flags="S")
			return packet
		except Exception as e:
			return f"Error: {e}"

	def udp(target, rcvport):
		try:
			packet = scapy.IP(dst=target) / scapy.UDP(dport=rcvport)
			return packet
		except Exception as e:
			return f"Error: {e}"

	print(f"{'Active devices detected:'}\n{'-' * 25}\n{'#':<5}{'IP Address':<20}\n{'-' * 25}")
	for i in range(len(ip_addresses)):
		print(f"{i + 1:<5}{ip_addresses[i]:<20}")
	print("-" * 25)
	key = int(input("Select a target ip address (Enter target number): "))
	choice = int(input(
		"\n\t[1] ICMP Ping Packet. \n\t[2] TCP Packet. \n\t[3] UDP Packet. \nSelect a packet type to send (Enter option number): "))

	num_packets = int(input("\nHow many packets you want to send?"))

	try:
		target = ip_addresses[key - 1]

		if (choice == 1):
			packet = icmp(target)
		elif (choice == 2):
			packet = tcp(target, rcvport=int(input("Enter destination port: ")))
		elif (choice == 3):
			packet = udp(target, rcvport=int(input("Enter destination port: ")))
		else:
			print("\nError, Invalid Input!")

		packet.show()
		send_choice = input("Do you want to send this packet? ([y] Yes./[n] No.): ").strip().lower()

		if send_choice == "y":
			scapy.send(packet, count=num_packets, verbose=1)
			print(f"{num_packets} Packets were sent.")
		else:
			print("Packet not sent.")

	except Exception as e:
		print(f"Error: {e}")

	time.sleep(2)


def traffic_monitoring(path="logs/traffic.txt", num_packets=10):
	def Determine_protocol(packet):
		if scapy.TCP in packet:
			return "TCP"
		elif scapy.UDP in packet:
			return "UDP"
		elif scapy.ICMP in packet:
			return "ICMP"
		elif scapy.ARP in packet:
			return "ARP"
		else:
			return "Unknown Protocol"

	def log_packets(log_file, stop_event):
		def process_packet(packet):
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			source_ip = packet[scapy.IP].src if scapy.IP in packet else "N/A"
			destination_ip = packet[scapy.IP].dst if scapy.IP in packet else "N/A"
			packet_size = len(packet)
			protocol = Determine_protocol(packet)
			log_line = f"{timestamp:<25}{protocol:<15}{source_ip:<15}{destination_ip:<20}{packet_size:<15}\n"
			with open(log_file, "a") as file:
				file.write(log_line)

		with open(log_file, "w") as file:
			file.write(f'{"-" * 90}\n')
			file.write(f"{'Timestamp':<25}{'Protocol':<15}{'Source IP':<15}{'Destination IP':<20}{'Packet Size':<15}\n")
			file.write(f'{"-" * 90}\n')
		print("Logging packets... ")

		scapy.sniff(prn=process_packet, store=False, stop_filter=lambda _: stop_event.is_set())

	def send_test_packet():
		ip = scapy.IP(dst="10.9.0.6")
		tcp = scapy.TCP(dport=80)
		packet = ip / tcp
		scapy.send(packet, count=num_packets)

	try:
		stop_event = threading.Event()  # Event to signal thread termination
		logging_thread = threading.Thread(target=log_packets, args=(path, stop_event))
		logging_thread.start()

		send_test_packet()
		time.sleep(2)  # Allow sniffing to capture packets before stopping

		# Signal the logging thread to stop and wait for it to finish
		stop_event.set()
		logging_thread.join()
		print("Traffic monitoring completed.")
	except Exception as e:
		print(f"Error: {e}")


def measure_network_performance(ip_addresses, path="logs/performance.txt", num_packets=10, interval=0.5):
	print(f"{'Active devices detected:'}\n{'-' * 25}\n{'#':<5}{'IP Address':<20}\n{'-' * 25}")
	for i in range(len(ip_addresses)):
		print(f"{i + 1:<5}{ip_addresses[i]:<20}")
	print("-" * 25)

	key = int(input("\nSelect a target IP address (Enter target number): "))
	target_ip = ip_addresses[key - 1]

	jitter_values = []
	latency_values = []
	throughput_values = []
	send_queue = Queue()
	response_queue = Queue()

	def send_packets():
		for i in range(num_packets):
			packet = scapy.IP(dst=target_ip) / scapy.ICMP()
			send_time = time.time()
			send_queue.put(send_time)  # Record send time
			scapy.send(packet, verbose=0)
			time.sleep(interval)

	def receive_replies():
		for _ in range(num_packets):
			response = scapy.sniff(filter=f"icmp and host {target_ip}", count=1, timeout=2)
			if response:
				receive_time = time.time()
				response_queue.put(receive_time)

	# Start threads
	try:
		send_thread = threading.Thread(target=send_packets)
		receive_thread = threading.Thread(target=receive_replies)

		send_thread.start()
		receive_thread.start()

		send_thread.join()
		receive_thread.join()
	except Exception as e:
		print(f"{'Error: '}{e}")

	# Analyze results
	try:
		with open(path, "a") as log:
			log.write(f"\nPerformance metrics for target IP: {target_ip}\n")
			log.write(
				f"{'Timestamp':<25}{'Latency (ms)':<15}{'Jitter (ms)':<15}{'Throughput (kbps)':<20}{'Data Rate (kbps)':<20}\n")
			log.write(f"{'-' * 85}\n")

			for i in range(num_packets):
				if send_queue.empty() or response_queue.empty():
					break

				send_time = send_queue.get()
				receive_time = response_queue.get()

				latency = (receive_time - send_time) * 1000  # ms
				latency_values.append(latency)

				if len(latency_values) > 1:
					jitter = abs(latency_values[-1] - latency_values[-2])
					jitter_values.append(jitter)
				else:
					jitter = 0

				throughput = (64 * 8) / (latency / 1000)  # kbps
				throughput_values.append(throughput)

				data_rate = throughput  # Simple assumption

				timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
				log.write(f"{timestamp:<25}{latency:<15.2f}{jitter:<15.2f}{throughput:<20.2f}{data_rate:<20.2f}\n")

				# Calculate averages
				avg_latency = sum(latency_values) / len(latency_values)
				avg_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0
				avg_throughput = sum(throughput_values) / len(throughput_values)
				avg_data_rate = avg_throughput

				# Real-time display of averages in terminal
				print(
					f"\rAvg Latency: {avg_latency:.2f} ms | Avg Jitter: {avg_jitter:.2f} ms | "
					f"Avg Throughput: {avg_throughput:.2f} kbps | Avg Data Rate: {avg_data_rate:.2f} kbps",
					end=""
				)

			# Final averages for conclusion
			avg_latency = sum(latency_values) / len(latency_values)
			avg_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0
			avg_throughput = sum(throughput_values) / len(throughput_values)
			avg_data_rate = avg_throughput

			log.write(f"\n{'-' * 85}\n{'Conclusion':<25}\n")
			log.write(
				f"Latency: {avg_latency:.2f} ms, Jitter: {avg_jitter:.2f} ms, "
				f"Throughput: {avg_throughput:.2f} kbps, Data Rate: {avg_data_rate:.2f} kbps\n"
			)
			print("\n\nNetwork performance metrics logged successfully.")
	except Exception as e:
		print(f"Error analyzing network performance: {e}")


def main():
	ip_addresses, _ = network_discovery()
	while (True):

		choice = int(input(
			"\n\t[1] Network Discovery. \n\t[2] Packet Analysis. \n\t[3] Custom Packet Creation and Transmission. \n\t[4] Traffic Monitoring and Logging. \n\t[5] Network performance measure. \n\t[6] Exit. \nSelect a menu option: "))

		if (choice == 1):
			network_discovery()
		elif (choice == 2):
			analyze_traffic(ip_addresses)
		elif (choice == 3):
			custom_packet(ip_addresses)
		elif (choice == 4):
			traffic_monitoring()
		elif (choice == 5):
			measure_network_performance(ip_addresses)
		elif (choice == 6):
			break
		else:
			print("Invalid input choice!")


if __name__ == "__main__":
	main()