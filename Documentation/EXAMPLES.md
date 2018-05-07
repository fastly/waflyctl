# Examples
## Provision a Service with OWASP rule set
`./waflyctl -apikey $FASTLY_TOKEN -serviceid BtYEP3WtWse5mGznpxxxx -tags OWASP`

## Add three rules to block mode on a Service with a WAF provisioned
`./waflyctl -apikey $FASTLY_TOKEN -serviceid BtYEP3WtWmx5mGznpxxxx -rules 94011,93110,93111 -action block`

## Delete a WAF previously provisioned
`./waflyctl -apikey $FASTLY_TOKEN -serviceid 7YCnicdpjTvxR2JdzNxxxx -delete`

## Customer with PerimeterX bot protection
`./waflyctl -apikey $FASTLY_TOKEN -domain myexample.com -with-perimeterx`

## Only edit OWASP object base on what it is set on the config file
`./waflyctl -apikey $FASTLY_TOKEN -domain myexample.com -owasp`

## Disable a WAF, stop it for blocking traffic if something goes horribly wrong
`./waflyctl -apikey $FASTLY_TOKEN -serviceid 7YCnicdpjTvxR2JdzNxxxx -status disable`
