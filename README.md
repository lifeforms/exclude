# Generate exclusion rules from ModSec audit log

## Requirements

A JSON ModSecurity audit log, usually found in `/var/log/modsec_audit.log`.

JSON logging format can be enabled using `SecAuditLogFormat JSON` in `mod_security2.conf`.

## Example

```sh
cat modsec_audit.log | ./exclude.py

SecRule REQUEST_FILENAME "@streq /" \
	"id:1000,phase:1,t:none,nolog,pass,\
		ctl:ruleRemoveTargetById=932160;ARGS:blah,\
		ctl:ruleRemoveTargetById=930120;ARGS:blah"

SecRule REQUEST_FILENAME "@streq /guttenberg/index.php/wp-json/wp/v2/posts/5/autosaves" \
	"id:1001,phase:1,t:none,nolog,pass,\
		ctl:ruleRemoveTargetById=942200;ARGS_NAMES,\
		ctl:ruleRemoveTargetById=942340;ARGS_NAMES,\
		ctl:ruleRemoveTargetById=942260;ARGS_NAMES,\
		ctl:ruleRemoveTargetById=942370;ARGS_NAMES"
```

## Future Work

* Set phase correctly
* In case multiple rules are generated, omit double rules
* Add `--short` command line option to activate short mode
* Add convenience options to filter the log, e.g. `--only-trans=AAAb`, `--only-path='/api/*'`, `--only-host=example.com`
* Detect URL schemes from common applications (e.g. WordPress, REST apis)
