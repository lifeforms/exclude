# Generate exclusion rules from ModSec audit log

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
* In case multiple rules are generated, 
* Filter inputs (e.g. on transaction id, path, hostname)
* Add command line option for short mode
* Detect URL schemes from common applications (e.g. WordPress, REST apis)