# -*- coding: utf-8 -*- 
# encoding=utf8  
import sys 
import socket
import argparse
import re
import time
import datetime
import itertools
import fuzzer as fz
from itertools import groupby
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
group = parser.add_mutually_exclusive_group(required=True)
fuzz = group.add_argument('--fuzz', default=0, type=str,  metavar='<Filenane>', nargs='+', help='File containing payloads')
auto_fuzz = group.add_argument('--auto-fuzz', metavar='<Length> <Step>', help='Enable the auto-fuzz mode', nargs=2)
csv = parser.add_argument('--csv', metavar='<Filename>', type=str, nargs='+', help='Output Log file')
param = parser.add_argument('--param', default=0, type=str, metavar='', nargs='+', help='Parameters to Fuzz')
args = parser.parse_args()

print Usage


#Create header for CSV logging
if args.csv:
	with open(args.csv[0], "w") as myfile:
		myfile.write("TimeStamp,Message Sent,Message Received,Time Elapsed"+"\n")
		csv_file = str(args.csv[0])

def getFuzzList(file):
	with open(file, 'r') as fuzz:
   	   	fuzzer = [line.rstrip() for line in fuzz]
   	   	print fuzzer	
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
	newtimestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d-%H:%M:%S.%f')[:-3]
	newtimestamp_tag = "52="+newtimestamp
	message = message.replace(timestamp_tag, newtimestamp_tag)
	return message,timestamp


def checksum(message):
	
	# The checksum field is removed from FIX message
	message = str(message[:-7])
	# Checksum is computed
	message_checksum = str(int(sum(bytearray(message)))%256).zfill(3)
	return message_checksum


def update_checksum(message):
	checksum_field = "10="
	# The checksum field is removed from FIX message
	message = str(message[:-7])
	# Checksum is computed
	message_checksum = str(int(sum(bytearray(message)))%256).zfill(3) # TODO: checksum(message)
	# A new updated message is created
	message_ok = message + checksum_field + message_checksum + '\x01'
	return message_ok


def update_bodylength(message, checksum):
	#9= extraction
	list_fix = []
	soh = '\x01'
	beginString = message.split(soh)[0]
	message = message.strip(beginString)
	message = str(message[:-8]) 
	
	bodylength = dict(re.findall("(?:^|\x01)(9)=(.*?)\x01", message))
	body_value = bodylength['9']


	message =  message.strip(soh+"9="+str(body_value)) + soh
	message = beginString+soh+"9="+str(len(message))+soh+message+"10="+checksum+soh

	list_fix.append(message)
	return message


def sendFuzzMessage(host, port, logonmsg, final):

	logonmsg,time_logon = update_timestamp(logonmsg)
	logonmsg = update_checksum(logonmsg)
	checksum_logonmsg = checksum(logonmsg)
	s = socket.socket()
	s.connect((host, port))
	s.send(logonmsg)

	for f in final:
		fix_request,time_fuzz = update_timestamp(f)
		checksum_msg = checksum(f)
		fix_request = update_bodylength(fix_request, checksum_msg)
		fix_request = update_checksum(fix_request)
		start_time = time.time()
		s.send(fix_request)
		print "\n[-] Sent: " + fix_request
		fix_response = s.recv(1024)
		print "[-] Received:" + fix_response
		elapsed_time = (time.time() - start_time)
		elapsed_time_ms = int(elapsed_time * 1000)
		if args.csv:
			csv(time_fuzz,fix_request,fix_response,elapsed_time_ms)
	s.close
	return  final, fix_response, elapsed_time_ms, s


def update_fix_message(message):
	message = update_timestamp(message)
	message = update_checksum(message)
	return message

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
	
	for i in fix_requests:
		if i in dict_final.keys():
			params = ",".join(dict_final[i]).split(",")

			for param in params:
				if args.auto_fuzz:
					print("[AUTO-FUZZ-MODE] Now fuzzing %d field:" ) %int(param)
					payloads = auto_fuzz(i, param)
				else:
					print("[Normal-FUZZ-MODE] Now fuzzing  field %d: " ) %int(param)
					payloads = normal_fuzz(i, param)

				for payload in payloads:
					final = list(fix_requests)
					final[final.index(i)] = payload
					sendFuzzMessage(args.host[0], args.port, logonmsg, final)

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
		fuzzed_message = fuzz_replace(request, param, payload)
		a = fuzz_replace(request,param,payload)
		normal_fuzz.append(a)
	return normal_fuzz

def auto_fuzz(request, param):
	length = int(args.auto_fuzz[0])
	step = int(args.auto_fuzz[1])
	auto_fuzz=[]
	for i in range(1,length,step):
		utf8_encoded = ""
		utf_payloads_test_inc = fz.utf8_gen(i)
		utf8_fixed_plain_test_inc = utf_payloads_test_inc[0][0]
		print utf_payloads_test_inc
		for field in utf8_fixed_plain_test_inc:
			utf8_encoded = utf8_encoded+field
			#print utf8_encoded
			a = fuzz_replace(request,param,utf8_encoded)
			auto_fuzz.append(a)
	return auto_fuzz

def csv(time,request,response,elapsed):
	with open(args.csv[0], "a") as myfile:
		myfile.write(str(time).rstrip('\n')+","+str(request).rstrip('\n')+","+str(response).rstrip('\n')+","+str(elapsed).rstrip('\n')+"\n")

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
		elif (re.search(r'58=' ,message_ok)):
			print "\n[INFO] This is a response, skipping...: " + message_ok
			try:
				FIX_id = re.search(r'49=(.*?)'+getSoh, message).group(1)
				print "\n[+] Fix server ID is: " + FIX_id
			except:
				print "\n[-]FIX server ID was not found"
		else:
			#Creating the list of messages to fuzz
			fix_requests.append(message_ok)

	if fix_requests:
		
		fuzz_it(logonmsg, fix_requests)
	else:
		print("[WARNING] No Messages to Fuzz were found")

			
if __name__ == "__main__":	
	main()

