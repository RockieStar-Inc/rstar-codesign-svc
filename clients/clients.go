// Package clients embeds the CI client script so the service can serve it.
package clients

import _ "embed"

//go:embed sign.sh
var SignScript []byte
