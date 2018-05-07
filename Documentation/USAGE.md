# Usage
waflyctl configuration file contains the default parameters to built or managed a WAF proposed by the
Fastly SOC. If needed please adjust them in waflyctl.toml, and or pass them via command line

```

A domain or service ID is required!

  -action string
        Select what action to take on the rules list and rule tags. Also overwrites action defined in config file, choices are: disabled, block, log.
  -apiendpoint string
        Fastly API endpoin, defaults to https://api.fastly.com (default "https://api.fastly.com")
  -apikey string
        [Required] API Key to use
  -config string
        Location of configuration file for waflyctl, defaults to waflyctl.toml (default "waflyctl.toml")
  -delete
        When set removes a WAF configuration created with waflyctl.
  -delete-logs
        When set removes WAF logging configuration.
  -domain string
        [Required] Domain to Provision, you can use Service ID alternatively
  -owasp
        When set edits the OWASP object base on the settings in the configuration file.
  -rules string
        Which rules to apply action on in a comma delimited fashion, overwrites ruleid defined in config file, example: 94011,93110,1000101..
  -serviceid string
        [Required] Service ID to Provision
  -status string
        Disable or Enable the WAF. A disabled WAF will not block any traffic.
  -tags string
        Which rules tags to add to the ruleset in a comma delimited fashion, overwrites tags defined in config file, example: OWASP,wordpress,php
  -with-perimeterx
        Enable if the customer has perimeterX enabled on the service as well as WAF. Helps fix null value logging.
```
