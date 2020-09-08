#!/usr/bin/env python3
import os, sys, subprocess, pickle, re
import sched, time

def send_message_title(title, message):
	"""Create a subprocess to call the notify-send command with a title and a message"""
	subprocess.Popen(['notify-send', '-t', '5000', title, message])
	return

def get_arp():
	"""Save the output of the arp command into a file, then read it and return it as an array"""
	os.system('arp > /tmp/arp_command_data')
	with open('/tmp/arp_command_data') as f:
		arp = f.read()
	# Split data into arp_records and remove useless arp_records
	arp_array = arp.split('\n')
	arp_array.pop(0)
	arp_array.pop(-1)

	return arp_array

def save_arp_dictionary(arp_dictionary):
	"""Save the dictionary into a file"""
	with open('/tmp/arp_dictionary.pkl', 'wb') as f:
		pickle.dump(arp_dictionary, f, pickle.HIGHEST_PROTOCOL)

def load_arp_dictionary():
	"""Load the dictionary from a file if its exists, else return an empty dictionary"""
	try:
		with open('/tmp/arp_dictionary.pkl', 'rb') as f:
			return pickle.load(f)
	except IOError:
		return {}

def analyze_suspicious_list(arp_dictionary, suspicious_list):
	"""Search a IP address which it's doing an ARP spoofing from the suspicious and notify the user"""
	for suspicious_item in suspicious_list:
		# Extract info from the list
		ip_address, old_mac_address, suspicious_mac_address = suspicious_item

		# Loop through all the IP addresses which have the same suspicious MAC address
		suspicious_ip_address_list = [ k for k in arp_dictionary.keys() if arp_dictionary[k] == suspicious_mac_address ] 
		for suspicious_ip_address in suspicious_ip_address_list:
			# If there is an other IP which has the same MAC address as the suspicious one, then notify the user
			if suspicious_ip_address != ip_address:
				title = "Warning ! ARP cache has been modified !"
				message = "{} could have changed the MAC address of {} from {} to {} to create an ARP poisoning"\
				.format(suspicious_ip_address, ip_address, old_mac_address, suspicious_mac_address)
				send_message_title(title, message)
				print(title + " " + message)

def main():
	"""
	Initialize variables, extract IP and MAC address and add them to dictionary.
	If an IP has a different MAC address, the old and new addresses are pushed into a list which will be analyzed
	"""
	arp_array = get_arp()
	arp_dictionary = load_arp_dictionary()
	suspicious_list = []

	for arp_record in arp_array:
		ip_search = re.search("(_gateway)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", arp_record)
		ip_address = ip_search.group(0) if ip_search else None

		mac_search = re.search("([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])", arp_record)
		mac_address = mac_search.group(0) if mac_search else None

		if ip_address and mac_address:
			# If ip_address is already known by the arp_dictionary, check if its MAC address is still the same
			if ip_address in arp_dictionary:
				old_mac_address = arp_dictionary[ip_address]
				# If the stored MAC address is different from the new one then add all the addresses into the suspicious list 
				if old_mac_address != mac_address:
					suspicious_list.append([ip_address, old_mac_address, mac_address])

			# Else, add it to arp_dictionary along with its MAC address
			else :
				arp_dictionary[ip_address] = mac_address

	save_arp_dictionary(arp_dictionary)
	analyze_suspicious_list(arp_dictionary, suspicious_list)
	# Call main function every 10 seconds
	s.enter(10, 1, main)

if __name__ == '__main__':
	try:
		s = sched.scheduler(time.time, time.sleep)
		s.enter(0, 1, main)
		s.run()
	except KeyboardInterrupt:
		print("End of programm")
		sys.exit()
