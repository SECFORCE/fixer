#Fixer Fuzzing Engine

import random, string, io
from random import randrange
from itertools import imap


SOH = '\x01'
equal = u"\u003D"


def fixed_utf8_string(n):
	result=u""
	for i in xrange(n):
		a = u"\\u%04x" % random.randrange(0x10000)
		result = result + a.decode('unicode-escape')
	return result

def utf8_gen(n):
	utf_lst_plain = []
	utf_lst_normal = []
	utf_payload_lists = []
	utf_lst_normal = list(fixed_utf8_string(n))
	utf_lst_plain = [e for e in utf_lst_normal if e not in (SOH, equal)]
	utf_payload_lists.append((utf_lst_plain[:], utf_lst_normal[:]))
	return utf_payload_lists
