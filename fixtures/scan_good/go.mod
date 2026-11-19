// Secure Go module pins: all at or above the last-known vulnerable releases.
module example.com/secure-sample

go 1.20

require (
	github.com/dgrijalva/jwt-go v3.2.1
	github.com/gorilla/websocket v1.5.3
	github.com/valyala/fasthttp v1.51.0
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/spf13/cobra v1.8.1
	gopkg.in/yaml.v2 v2.4.0
)
