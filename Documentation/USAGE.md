# Usage
waflyctl configuration file contains the default parameters to build and also managed a WAF. 
If needed please adjust them in waflyctl.toml, and or pass them via command line.
```
Usage of waflyctl:
  -action string
    	Select what action to take on the rules list and rule tags. Also overwrites action defined in config file, choices are: disabled, block, log.
  -apiendpoint string
    	Fastly API endpoint to use. (default "https://api.fastly.com")
  -apikey string
    	[Required] API Key to use
  -config string
    	Location of configuration file for waflyctl. (default "/Users/jhernandez/.waflyctl.toml")
  -configuration-set string
    	Changes WAF configuration set to the provided one]
  -delete
    	When set removes a WAF configuration created with waflyctl.
  -delete-logs
    	When set removes WAF logging configuration.
  -domain string
    	[Required] Domain to Provision, you can use Service ID alternatively
  -enable-logs-only
    	Add logging configuration only to the service, the tool will not make any other changes, can be paired with-perimeterx
  -list-all-rules string
    	List all rules available on the Fastly platform for a given configuration set. Must pass a configuration set ID
  -list-configuration-sets
    	List all configuration sets and their status
  -list-rules
    	List current WAF rules and their status
  -owasp
    	When set edits the OWASP object base on the settings in the configuration file.
  -publisher string
    	Which rule publisher to use in a comma delimited fashion, overwrites publisher defined in config file, choices are: owasp, trustwave, fastly
  -rules string
    	Which rules to apply action on in a comma delimited fashion, overwrites ruleid defined in config file, example: 1010010,931100,931110..
  -serviceid string
    	[Required] Service ID to Provision
  -status string
    	Disable or Enable the WAF. A disabled WAF will not block any traffic, also disabling a WAF does not change rule statuses on its configure policy.
  -tags string
    	Which rules tags to add to the ruleset in a comma delimited fashion, overwrites tags defined in config file, example: wordpress,language-php,drupal
  -with-perimeterx
    	Enable if the customer has perimeterX enabled on the service as well as WAF. Helps fix null value logging.
```
