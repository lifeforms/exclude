#!/usr/bin/env python3

import fileinput
import json
import re
from urllib.parse import urlparse, parse_qs

def parse_alert(logentry: dict):
	"""Parses a single entry (decoded JSON) from modsec_audit.log"""
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
	"""Returns triggered ruleId and target (ex: ARGS:foo) from an audit message."""
	id = None
	target = None

	id_re = re.search(r'\[id \"(\d+)\"\]', m)
	if id_re is not None:
		id = int(id_re.group(1))
		if (949000 <= id <= 949999) or (980000 <= id <= 980999):
			id = None

	target_re = re.search(
		r'ARGS_NAMES|ARGS:\w+|REQUEST_BODY|REQUEST_COOKIES:\w+|REQUEST_HEADERS:\w+', m)
	if target_re is not None:
		target = target_re.group(0)

	return {'id': id, 'target': target}

def parse_request_line(l: str):
	"""Returns method, path and args from a request line."""
	line_re = re.search(r'^(\w+) (.*) HTTP/\d(?:\.\d?)$', l)
	method = line_re.group(1)
	url = urlparse(line_re.group(2))
	path = url.path
	args = parse_qs(url.query)
	return {'method': method, 'path': path, 'args_get': args}

def generate_exclusion(alert):
	exclusion = dict(alert)
	exclusion['phase'] = 1 # TODO: infer from args
	return exclusion

def emit_rule(exclusion):
	"""Generates a ModSec exclusion rule for an alert."""
	global ruleid
	r = f'SecRule REQUEST_FILENAME "@streq {exclusion["line"]["path"]}" \\\n'
	r += f'\t"id:{ruleid},phase:{exclusion["phase"]},t:none,nolog,pass'
	for t in exclusion['triggers']:
		if t['id']:
			r += f',\\\n\t\tctl:ruleRemoveTargetById={t["id"]};{t["target"]}'

	r += '"\n'

	ruleid = ruleid + 1
	return r

ruleid = 1000
for logline in fileinput.input():
	logentry = json.loads(logline)
	alert = parse_alert(logentry)
	exclusion = generate_exclusion(alert)
	rule = emit_rule(exclusion)
	print(alert)
	print(rule)
