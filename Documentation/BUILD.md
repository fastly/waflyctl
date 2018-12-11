#  Build

Install [Go](https://golang.org/doc/install) and run the following
commands:

```
cd waflyctl
go get github.com/BurntSushi/toml github.com/sethvargo/go-fastly/fastly \
	gopkg.in/alecthomas/kingpin.v2 gopkg.in/resty.v1
go build waflyctl.go
./waflyctl
```

Centos Install:
```
yum -y install golang
go get -v github.com/fastly/waflyctl
```
