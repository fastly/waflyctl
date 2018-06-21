# Requirements
- Have a Fastly API Key in-hand with edit privileges
- Have a service behind Fastly
- Have WAF be enabled for your account
- Have a GITHUB token with repo scope

# Installation
- `export HOMEBREW_GITHUB_API_TOKEN=<your new git token>`, may want to put this on your bash
profile
- `brew install fastly/tap/waflyctl` 
- grab a copy of the [config](https://github.com/fastly/waflyctl/blob/master/config_examples/waflyctl.fastly_soc_example.toml) file and place it under `~/.waflyctl.toml` where the tool defaults to.
