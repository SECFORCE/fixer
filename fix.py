# -*- coding: utf-8 -*- 
# encoding=utf8  
#!/usr/bin/env python
# Fixer: a FIX protocol fuzzer
#     ______    _                       
#    / ____/   (_)   _  __  ___    _____
#   / /_      / /   | |/_/ / _ \  / ___/
#  / __/     / /   _>  <  /  __/ / /    
# /_/       /_/   /_/|_|  \___/ /_/                                           
# 
#                          
# http://www.secforce.com  
# Authors:
# thanos.polychronis <at> secforce.com, lorenzo.vogelsang <at> secforce.com
#################################################################################


import sys 
import socket
import argparse
import re
import time
import datetime
import itertools
import fuzzer as fz
from itertools import groupby
from socket import error as SocketError

__author__ = "Thanos Polychronis and Lorenzo Vogelsang"
__copyright__ = "Copyright 2017, SECFORCE LTD"
__license__ = "GPL"
__version__ = "0.1"


reload(sys) 
sys.setdefaultencoding('utf8')

getSoh = ""
standard = ['56', '8', '35', '9', '35', '34', '10', '49', '52', '369','']

Usage= ('\n-----------------------------------------------------------------------------------\n'
          'Examples:\n\n'
          '  python fix.py --host=127.0.0.1 --port=11310 --input-file=fix.raw --fuzz=/tmp/payloads.txt\n'
          '  python fix.py --host=127.0.0.1 --port=11310 --input-file=fix.raw --csv=results.xls --fuzz=/tmp/payloads.txt --param 11,38\n'
          '  python fix.py --host=127.0.0.1 --port=11310 --input-file=fix.raw --csv=results.xls --auto-fuzz 1000 2 --param 55\n'
          '\n----------------------------------------------------------------------------------')

                               
parser = argparse.ArgumentParser(description='FIX values', usage=Usage)
host = parser.add_argument('--host',  type=str, nargs='+', help='the IP of the FIX server', required=True)
port = parser.add_argument('--port', type=int, help='the listening port', required=True)
input_file = parser.add_argument('--input-file', type=str, nargs=1, help='PCAP file with FIX authentication and action(s) to fuzz', required=True)
seq_start = parser.add_argument('--seq-start', type=int, help='The start number for the sequence ID (inc initial logon), defaults to "2"', required=False, default=2)
group = parser.add_mutually_exclusive_group(required=True)
fuzz = group.add_argument('--fuzz', default=0, type=str,  metavar='<Filename>', nargs='+', help='File containing payloads')
auto_fuzz = group.add_argument('--auto-fuzz', metavar='<Length> <Step>', help='Enable the auto-fuzz mode', nargs=2)
sequential_fuzz = group.add_argument('--sequential-fuzz', action='store_true', help='Enable the sequential-fuzz mode')
no_fuzz = group.add_argument('--no-fuzz', action='store_true', help='Just send the original unfettered version from file')
csv = parser.add_argument('--csv', metavar='<Filename>', type=str, nargs='+', help='Output Log file')
param = parser.add_argument('--param', default=0, type=str, metavar='', nargs='+', help='Parameters to Fuzz')
args = parser.parse_args()

print Usage


#Create header for CSV logging
if args.csv:
	with open(args.csv[0], "w") as myfile:
		myfile.write("TimeStamp,Message Sent,Send Seq,Message Received,Time Elapsed"+"\n")
		csv_file = str(args.csv[0])

def getFuzzList(file):
	with open(file, 'r') as fuzz:
   	   	fuzzer = [line.rstrip() for line in fuzz]
   	return fuzzer

def timestampGen():
	ts = time.time()
	newtimestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d-%H:%M:%S.%f')[:-3]
	return newtimestamp

def update_timestamp(message):
	#52= extraction
	timestamp_fix = dict(re.findall("(?:^|\x01)(52)=(.*?)\x01", message)) 
	#Extraction of the actual timestamp
	timestamp = timestamp_fix['52']
	#Whole timestamp tag+field
	timestamp_tag = "52="+timestamp
	ts = time.time()
	newtimestamp = datetime.datetime.utcfromtimestamp(ts).strftime('%Y%m%d-%H:%M:%S.%f')[:-3]
	newtimestamp_tag = "52="+newtimestamp
	message = message.replace(timestamp_tag, newtimestamp_tag)
	return message,timestamp


def update_checksum(message):
	checksum_field = "10="
	# The checksum field is removed from FIX message
	message = str(message[:-7])
	# Checksum is computed
	message_checksum = str(int(sum(bytearray(message)))%256).zfill(3) # TODO: checksum(message)
	# A new updated message is created
	message_ok = message + checksum_field + message_checksum + '\x01'
	return message_ok


def update_bodylength(message):
	#9= extraction
	list_fix = []
	soh = '\x01'
	beginString = message.split(soh)[0]
	message = message.strip(beginString)
	message = str(message[:-8]) 
	
	bodylength = dict(re.findall("(?:^|\x01)(9)=(.*?)\x01", message))
	body_value = bodylength['9']


	message =  message.strip(soh+"9="+str(body_value)) + soh
	message = beginString+soh+"9="+str(len(message))+soh+message+"10=001"+soh

	list_fix.append(message)
	return message


def sendFuzzMessage(host, port, logonmsg, final, current_seq_num):
	requested_seq_num = None
	logonmsg,time_logon,current_seq_num = update_fix_message(logonmsg, current_seq_num)
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, port))
		s.send(logonmsg)
		print "\n[-] Logon Sent: " + logonmsg.replace('\x01', '^')
		fix_response = s.recv(1024)
		print "[-] Logon Received:" + fix_response.replace('\x01', '^')

		# logon error detected
		if re.findall("\x0135=5\x01", fix_response):
			logout_error_message = re.findall("(?:\x0158=)(.*?)\x01", fix_response)[0]
			print "\n[*] Server sent Logout message.  Error text is: " + logout_error_message
			if 'MsgSeqNum' in logout_error_message:
				expected_seq_num = re.findall("(?:expecting )([0-9]+)(?: but received)", logout_error_message)[0]
				print "\n[*] Sequence number expected is: " + expected_seq_num + " but we gave: " + str(current_seq_num-1) \
					  + " will retry logon using expected sequence number"
				# have to restart socket as server doesn't play otherwise
				s.close
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))
				logonmsg, time_logon, current_seq_num = update_fix_message(logonmsg, int(expected_seq_num))
				s.send(logonmsg)
				print "\n[-] Logon Sent: " + logonmsg.replace('\x01', '^')
				fix_response = s.recv(1024)
				print "[-] Logon Received:" + fix_response.replace('\x01', '^')

		for fix_message in final:
			fix_request,time_fuzz,current_seq_num = update_fix_message(fix_message, current_seq_num)
			start_time = time.time()
			s.send(fix_request)
			print "\n[-] Payload Sent: " + fix_request.replace('\x01', '^')

			fix_response = s.recv(1024)
			print "[-] Payload Received:" + fix_response.replace('\x01', '^')
			if re.findall("(?:\x0135=)2\x01", fix_response):
				print "\n[*] Server sent ResendRequest message, extracting sequence ID for future messages"
				requested_seq_num = int(re.findall("(?:\x017=)([0-9]+)\x01", fix_response)[0])
				print "\n[*] Sequence number requested is: " + str(requested_seq_num) + " but we are at: " + str(current_seq_num-1) \
					  + " will use requested sequence number for future payloads.  Also, this payload will not be re-fired"
			if not fix_response:
				print "\n[*] Server did not send a response - could indicate crash occurred"
				fix_response = 'Blank response - investigate this and previous payload'

		s.close
	except SocketError as e:
		print ('Socket error: ' + str(e))
		fix_response = 'Socket error: ' + str(e)

	elapsed_time = (time.time() - start_time)
	elapsed_time_ms = int(elapsed_time * 1000)
	if args.csv:
		apend_to_csv(time_fuzz, fix_request, str(int(current_seq_num)-1), fix_response, elapsed_time_ms)
	if requested_seq_num:
		return requested_seq_num
	else:
		return current_seq_num


def update_seqnum(message, current_seq_num):
	# 34= extraction
	seq_fix = dict(re.findall("(?:^|\x01)(34)=(.*?)\x01", message))
	# Extraction of the actual seq num
	seq = seq_fix['34']
	# Whole seq tag+field
	seq_tag = "34=" + seq
	new_seq = str(current_seq_num)
	new_check_sum_tag = "34=" + new_seq
	message = message.replace(seq_tag, new_check_sum_tag)
	current_seq_num += 1
	return message, current_seq_num


def update_fix_message(message, current_seq_num):
	message,time_logon = update_timestamp(message)
	message, current_seq_num = update_seqnum(message, current_seq_num)
	message = update_bodylength(message)
	message = update_checksum(message)
	return message, time_logon, current_seq_num


def fix2log(message):
	message = message.replace(getSoh, "^")
	return message


# fuzz_it will route fuzz request trhough all available options
def fuzz_it(logonmsg, fix_requests):
	print("[+] %d Fix requests will now be fuzzed") % len(fix_requests)
	testing = []
	
	d=dict()
	testing=dict()

	for request in fix_requests:
		#request.split(getSoh)[0].split('=')
		d.__setitem__(request, [request.split('=')[0] for request in request.split(getSoh)])
	
	for key, value in d.iteritems():	
		l = ",".join(value).split(",")
					
		if args.param:
			args_param_str = ''.join(args.param).split(",")
			for argument in args_param_str:
				if (argument not in l) or (argument in standard):
					print ("[-] Provided Parameter %s was not found or is standard. Exiting..") %str(argument)
					continue
				else:
					print ("[+] Found parameter %s in request %d") %(argument,d.keys().index(key))

					if key in testing:
						testing[key].append(argument)
					else:
						testing.__setitem__(key,[argument])
		else: 
			print "[+] No parameters were provided. Fuzzing everything\n"
			testing.__setitem__(key,[x for x in l if x not in standard])
	print ("\n[INFO] The requests and parameters to Fuzz! %s") %testing
	print "\n"
	test(fix_requests, testing, logonmsg)


def test(fix_requests, dict_final, logonmsg):
	current_seq_num = args.seq_start

	# send an unfettered FIX message to test the thing works
	print("Sending the first message from the input file as an unfettered FIX message\n")
	initial = list()
	initial.append(str(fix_requests[0]))
	current_seq_num = sendFuzzMessage(args.host[0], args.port, logonmsg, initial, current_seq_num)

	print('-=-=-=-Fuzzing start-=-=-=-\n')

	try:
		for message_to_fuzz in fix_requests:
			if message_to_fuzz in dict_final.keys():
				params = ",".join(dict_final[message_to_fuzz]).split(",")

				for param in params:
					if args.auto_fuzz:
						print("[AUTO-FUZZ-MODE] Now fuzzing field: %d" ) %int(param)
						payloads = auto_fuzz(message_to_fuzz, param)
					elif args.sequential_fuzz:
						print("[SEQUENTIAL-FUZZ-MODE] Now fuzzing field: %d") % int(param)
						payloads = sequential_fuzz(message_to_fuzz, param)
					elif args.no_fuzz:
						print("No further action needed as not fuzzing, just sending unfettered")
					else:
						print("[NORMAL-FUZZ-MODE] Now fuzzing field: %d") %int(param)
						payloads = normal_fuzz(message_to_fuzz, param)

					for payload in payloads:
						final = list(fix_requests)
						final[final.index(message_to_fuzz)] = payload
						current_seq_num = sendFuzzMessage(args.host[0], args.port, logonmsg, final, current_seq_num)
	except KeyboardInterrupt:
		# if user "Ctrl-C", stop processing gracefully
		print('Exiting...')
		exit(1)


def fuzz_replace(request, param, payload):
	newPart=re.findall('\d+', param)
	newPart=str(newPart[0])+ '=' + payload
	#Detecting the existing field=value
	part_to_fuzz = dict(re.findall("(?:^|\x01)("+param+")=(.*?)\x01", request))
	part_to_fuzz_value = part_to_fuzz[param]
	part_to_fuzz_ok = param+"="+part_to_fuzz_value
	#Baking the fuzz message
	request_fuzz = request.replace(part_to_fuzz_ok, newPart)
	return request_fuzz


def normal_fuzz(request, param):
	normal_fuzz=[]
	for payload in getFuzzList(args.fuzz[0]):
		a = fuzz_replace(request,param,payload)
		normal_fuzz.append(a)
	return normal_fuzz


def sequential_fuzz(request, param):

	sequential_fuzz=[]

	payloads_list = list()
	for i in xrange(10000):
		a = u"\\u%04x" % i
		payloads_list.append(a.decode('unicode-escape'))

	for payload in payloads_list:
		a = fuzz_replace(request,param,payload)
		sequential_fuzz.append(a)
	return sequential_fuzz


def auto_fuzz(request, param):
	length = int(args.auto_fuzz[0])
	step = int(args.auto_fuzz[1])
	auto_fuzz=[]
	for i in range(1,length,step):
		utf8_encoded = ""
		utf_payloads_test_inc = fz.utf8_gen(i)
		utf8_fixed_plain_test_inc = utf_payloads_test_inc[0][0]
		for field in utf8_fixed_plain_test_inc:
			utf8_encoded = utf8_encoded+field
			a = fuzz_replace(request,param,utf8_encoded)
			auto_fuzz.append(a)
	return auto_fuzz


def message_cleaner(message):
	SOH = '\x01'
	newline = u"\u000A"
	carriagereturn = u"\u000D"
	comma = u"\u002C"

	clean_message = message.rstrip('\n').replace(SOH, '^').replace(newline, '[{nl}]').replace(carriagereturn, '[{cr}]').replace(comma, '[{com}]')
	return clean_message


def apend_to_csv(time, request, req_seq, response, elapsed):
	clean_request = message_cleaner(request)
	clean_response = message_cleaner(response)
	with open(args.csv[0], "a") as myfile:
		myfile.write(str(time).rstrip('\n')+","+str(clean_request)+","+str(req_seq)+","+str(clean_response)+","+str(elapsed).rstrip('\n')+"\n")

def main():
	FIX_id=""
	fix_requests = []
	logonmsg = ""
	with open(args.input_file[0]) as f2:
		lines = f2.read().splitlines()
		raw_messages = "".join(lines)
    	#Beginstring identification
    	beginString = raw_messages.split('\x01')[0]
    	print("[+] Begin string is "+beginString)
    	messages_split = raw_messages.split(beginString)
	for message in messages_split:
		#Identify requests and Logon Messages
		message_ok = beginString+message
		if message_ok == beginString:
			continue
		if (len(message_ok) <= 0):
			print "\n[INFO] Message not found"
		elif (logonmsg=="") and (re.search(r'35=A'+getSoh,message_ok)):
			print "\n[+] Found Logon Message: " + message_ok
			logonmsg = message_ok
		elif (logonmsg!="" and (re.search(r'30=0' ,message)) or (re.search(r'35=A'+getSoh ,message))):
			print "\n[INFO] Message is Not Logon:  " + message_ok
#		elif (re.search(r'58=' ,message_ok)):
#			print "\n[INFO] This is a response, skipping...: " + message_ok
#			try:
#				FIX_id = re.search(r'49=(.*?)'+getSoh, message).group(1)
#				print "\n[+] Fix server ID is: " + FIX_id
#			except:
#				print "\n[-]FIX server ID was not found"
		else:
			#Creating the list of messages to fuzz
			fix_requests.append(message_ok)

	if fix_requests:
		
		fuzz_it(logonmsg, fix_requests)
	else:
		print("[WARNING] No Messages to Fuzz were found")

			
if __name__ == "__main__":	
	main()

