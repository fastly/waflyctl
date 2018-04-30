# ![Fastly WAF Control Tool](images/waflyctl_logo.png)
Allows you to provision a waf object with pre-determine rules, OWASP config, response, and logging endpoints. Also manage rules, and their status. 

## Requirements 
- Have a Fastly API Key in-hand with edit privilages
- optionally if you are not running Darwin/x86 (OSX) then see [Build](#build)

## Installation 
- `git clone https://github.com/fastly/waflyctl.git .`
- `cd waflyctl && chmod +x waflyctl`
- `./waflyctl`

## Usage
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

## Example
#### Provision a Service with OWASP rule set
`./waflyctl -serviceid BtYEP3WtWse5mGznpxxxx -apikey $FASTLY_TOKEN -tags OWASP`

#### Add three rules to block mode on a Service with a WAF provisioned
`./waflyctl -serviceid BtYEP3WtWmx5mGznpxxxx -apikey $FASTLY_TOKEN -rules 94011,93110 -action block`

#### Delete a WAF previously provisioned
`./waflyctl -serviceid 7YCnicdpjTvxR2JdzNxxxx -delete -apikey $FASTLY_TOKEN`

#### Customer with PerimeterX bot protection 
`./waflyctl -apikey $FASTLY_TOKEN -domain myexample.com -with-perimeterx`

#### Only edit OWASP object base on what it is set on the config file
`./waflyctl -apikey $FASTLY_TOKEN -domain myexample.com -owasp`

#### Disable a WAF, stop it for blocking traffic if something goes horribly wrong
`./waflyctl -apikey $FASTLY_TOKEN -serviceid 7YCnicdpjTvxR2JdzNxxxx -status disable`

##  Build
 - install [Go](https://golang.org/doc/install) 
 - `cd soc/waflyctl`
 - `go get github.com/BurntSushi/toml github.com/sethvargo/go-fastly/fastly gopkg.in/resty.v1`
 - `go build waflyctl.go`
 - `./waflyctl`
