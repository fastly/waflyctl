# Requirements

- Have a Fastly API Key in-hand with edit privileges
- Have a service behind Fastly
- Have [Fastly WAF (Legacy)](https://docs.fastly.com/en/guides/web-application-firewall-legacy) enabled for your account. (WAF-NG users should use the [API](https://developer.fastly.com/reference/api/waf/) / [Terraform provider](https://registry.terraform.io/providers/fastly/fastly/latest/docs/resources/service_waf_configuration) instead)
- You will also need to grab a copy of the
  [config](https://github.com/fastly/waflyctl/blob/master/config_examples/waflyctl.toml.example)
  file and place it under `~/.waflyctl.toml` where the tool defaults to.

# Mac Installation

To install the latest release in macOS:

```
brew install fastly/tap/waflyctl
```

Alternatively, to use unreleased code from the master branch:

```
brew install --HEAD fastly/tap/waflyctl
```

# Other OS Installation

Install Go: https://golang.org/doc/install

Download, install, build waflyctl + dependencies:

```
go get -v github.com/fastly/waflyctl
```
