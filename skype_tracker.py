#!/usr/bin/python

import argparse, os, time
import pygeoip
from scapy.all import *


parser = argparse.ArgumentParser(description="Track Skype call locations")

parser.add_argument('-t', help="set time limit for capture", dest="time", default=15)
required = parser.add_argument_group("Required Arguments")
required.add_argument('-d', help="GeoIpDatabase *.dat file for locating IP Address", dest="datfile", required=True)
required.add_argument('source',help="IP address of source machine")


args = parser.parse_args()

ips = dict()
ports = {}


status = "Running"
start = time.time()
timelapse = None
def screen():
	os.system("clear")
	print status()
	print "============================================================================"
	print "Destination\tCount"
	print "============================================================================"

	for ip in ips:
		print str(ip) + "\t" + str(ips[ip])
	
def getSummary(pkt):
	if IP in pkt:
		ip_dst = pkt[IP].dst
		if pkt[IP].src == args.source:
			if ip_dst not in ips:
				ips[ip_dst] = 1
				#print "\r\r[+] New IP \t\t" + str(ip_dst) + "\t count => \t" + str(ips[ip_dst])
			else:
				count = ips[ip_dst] + 1
				ips[ip_dst] = count
				#print "\r\r[+] Existing IP \t" + str(ip_dst) + "\t count => \t " + str(ips[ip_dst])
			screen()

#	if TCP in pkt:
#		srcport = pkt[TCP].sport
#		dstport = pkt[TCP].dport
#		print srcport
#		print dstport
timelapse = 0


def status():
	return "Finding Target IP Address for " + str(int(args.time)) + " seconds\tTimelapse: " + str(time.time() - start)[:1]

screen()


def stopfilter(x):
	now = time.time()	
	global timelapse	
	timelapse = now - start
	if (now - start > int(args.time)):
		return True
	else:
		return False
	
sniff(prn=getSummary, stop_filter=stopfilter, filter="udp")

highest = max(ips, key=ips.get)
print "\n\n[*]Highest count:\t"+highest
print "[*] Finding Location..."
GeoIPDatabase = arg.datfile
ipData = pygeoip.GeoIP(GeoIPDatabase)
record = ipData.record_by_name(highest)
print("The geolocation for IP Address %s is:" % highest)
print("Accurate Location: %s, %s, %s" % (record['city'], record['region_code'], record['country_name']))
print("General Location: %s" % (record['metro_code']))
