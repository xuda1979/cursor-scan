// Vulnerable Go module pins for P3 dependency-risk fixture
module example.com/vuln-sample

go 1.19

require (
	github.com/dgrijalva/jwt-go v3.2.0
	github.com/gorilla/websocket v1.4.2
	github.com/valyala/fasthttp v1.25.0
	github.com/hashicorp/go-retryablehttp v0.6.5
	github.com/spf13/cobra v0.0.3
	gopkg.in/yaml.v2 v2.2.1
)

require gopkg.in/yaml.v2 v2.2.4 // indirect
