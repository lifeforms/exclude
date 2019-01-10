#!/usr/bin/env python3

import fileinput
import json
import re
from urllib.parse import urlparse, parse_qs

def parse_alert(alert):
	result = {}
	result['line'] = parse_request_line(alert['request']['request_line'])

	result['triggers'] = []
	for m in alert['audit_data']['messages']:
		result['triggers'].append(parse_message(m))

	if 'body' in alert['request']:
		result['args_post'] = parse_qs(alert['request']['body'][0])
	else:
		result['args_post'] = {}
	result['args'] = {**result['line']['args_get'], **result['args_post']}
	return result

def parse_message(m):
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

def parse_request_line(l):
	line_re = re.search(r'^(\w+) (.*) HTTP/\d(?:\.\d?)$', l)
	method = line_re.group(1)
	url = urlparse(line_re.group(2))
	path = url.path
	args = parse_qs(url.query)
	return {'method': method, 'path': path, 'args_get': args}

for log_line in fileinput.input():
	ex = parse_alert(json.loads(log_line))
	print(ex)
