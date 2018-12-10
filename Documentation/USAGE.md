# Usage
waflyctl configuration file contains the default parameters to build and also managed a WAF. 
If needed please adjust them in waflyctl.toml, and or pass them via command line.
```
usage: waflyctl --apikey=APIKEY [<flags>]

Fastly WAF Control Tool

Flags:
  --help                     Show context-sensitive help (also try --help-long
                             and --help-man).
  --version                  Show application version.
  --action=ACTION            Action to take on the rules list and rule tags.
                             Overwrites action defined in config file. One of:
                             disabled, block, log.
  --apiendpoint="https://api.fastly.com"
                             Fastly API endpoint to use.
  --apikey=APIKEY            API Key to use. Required.
  --backup                   Store a copy of the WAF configuration in
                             /Users/guest/.waflyctl-<service-id>.rules.
  --config="/Users/guest/.waflyctl.toml"
                             Location of configuration file for waflyctl.
  --configuration-set=CONFIGURATION-SET
                             Changes WAF configuration set to the provided one.
  --delete                   Remove a WAF configuration created with waflyctl.
  --delete-logs              When set removes WAF logging configuration.
  --domain=DOMAIN            Domain to Provision. You can use Service ID
                             alternatively.
  --enable-logs-only         Add logging configuration only to the service. No
                             other changes will be made. Can be used together
                             with --with-perimeterx
  --list-all-rules=CONFIGURATION-SET
                             List all rules available on the Fastly platform for
                             a given configuration set.
  --list-configuration-sets  List all configuration sets and their status.
  --list-rules               List current WAF rules and their status.
  --owasp                    Edit the OWASP object base on the settings in the
                             configuration file.
  --provision                Provision a new WAF or update an existing one.
  --publisher=PUBLISHER      Which rule publisher to use in a comma delimited
                             fashion. Overwrites publisher defined in config
                             file. Choices are: owasp, trustwave, fastly
  --rules=RULES              Which rules to apply action on in a comma delimited
                             fashion. Overwrites ruleid defined in config file.
                             Example: 1010010,931100,931110.
  --serviceid=SERVICEID      Service ID to Provision.
  --status=STATUS            Disable or Enable the WAF. A disabled WAF will not
                             block any traffic. In addition disabling a WAF does
                             not change rule statuses on its configure policy.
                             One of: disable, enable.
  --tags=TAGS                Which rules tags to add to the ruleset in a comma
                             delimited fashion. Overwrites tags defined in
                             config file. Example:
                             wordpress,language-php,drupal.
  --with-perimeterx          Enable if the customer has PerimeterX enabled on
                             the service as well as WAF. Helps fix null value
                             logging.
  --with-shielding           Enable if the customer has shielding enabled on the
                             service. Helps fix multiple events with duplicate
                             request IDs.
