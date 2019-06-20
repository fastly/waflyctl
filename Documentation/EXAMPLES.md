# Examples

Replace <service_id> and <configuration_set_id> where appropriate.

## Provision a Service with OWASP rule set
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --tags OWASP --comment "WAF deployment"`

## Add three rules to block mode on a Service with a WAF provisioned
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --rules 1010010,931100,931110 --action block`

## Delete a WAF previously provisioned
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --delete`

## Customer with PerimeterX bot protection
`waflyctl --apikey $FASTLY_TOKEN --domain myexample.com --with-perimeterx`

## Only edit OWASP object base on what it is set on the config file
`waflyctl --apikey $FASTLY_TOKEN --domain myexample.com --owasp`

## Listing all configuration sets available on the fastly platform
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --list-configuration-sets`

## Listing all rules available under a configuration set
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --list-all-rules <configuration_set_id>`

## Listing all rules and their status for a service
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --list-rules`

## Set all rules of publisher owasp to logging 
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --publisher owasp --action log`

## Disable WAF in case of an emergency
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --status disable`

## Customer with shielding (deprecated - no longer required)
`waflyctl --apikey $FASTLY_TOKEN --serviceid <service_id> --enable-logs-only --with-shielding`
