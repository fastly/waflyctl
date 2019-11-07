# Build

Install [Go](https://golang.org/doc/install) and run the following
commands:

```
cd waflyctl
go get github.com/BurntSushi/toml github.com/fastly/go-fastly \
  gopkg.in/alecthomas/kingpin.v2 gopkg.in/resty.v1
go build -mod=vendor waflyctl.go
./waflyctl
```
