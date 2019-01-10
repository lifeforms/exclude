#!/usr/bin/env python3

import fileinput
import json
import re
from urllib.parse import urlparse, parse_qs

def parse_alert(logentry: dict):
	result = {}
	result['line'] = parse_request_line(logentry['request']['request_line'])

	result['triggers'] = []
	for m in logentry['audit_data']['messages']:
		result['triggers'].append(parse_message(m))

	if 'body' in logentry['request']:
		result['args_post'] = parse_qs(logentry['request']['body'][0])
	else:
		result['args_post'] = {}
	result['args'] = {**result['line']['args_get'], **result['args_post']}
	return result

def parse_message(m: str):
	id = None
	target = None

	id_re = re.search(r'\[id \"(\d+)\"\]', m)
	if id_re is not None:
		id = int(id_re.group(1))
		if (949000 <= id <= 949999) or (980000 <= id <= 980999):
			id = None

	target_re = re.search(
		r'ARGS_NAMES|ARGS:(?:\w\.)+|REQUEST_BODY|REQUEST_COOKIES:\w+|REQUEST_HEADERS:\w+', m)
	if target_re is not None:
		target = target_re.group(0)

	return {'id': id, 'target': target}

def parse_request_line(l: str):
	line_re = re.search(r'^(\w+) (.*) HTTP/\d(?:\.\d?)$', l)
	method = line_re.group(1)
	url = urlparse(line_re.group(2))
	path = url.path
	args = parse_qs(url.query)
	return {'method': method, 'path': path, 'args_get': args}

for logline in fileinput.input():
	logentry = json.loads(logline)
	alert = parse_alert(logentry)
	print(alert)
