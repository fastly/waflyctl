# Requirements

* Have a Fastly API Key in-hand with edit privileges
* Have a service behind Fastly
* Have WAF enabled for your account
* You will also need to grab a copy of the
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
