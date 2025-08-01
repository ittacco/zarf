module github.com/zarf-dev/zarf/hack/schema

go 1.24.4

replace github.com/zarf-dev/zarf => ../..

require (
	github.com/invopop/jsonschema v0.13.0
	github.com/zarf-dev/zarf v0.0.0-local // grabbed from local
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
