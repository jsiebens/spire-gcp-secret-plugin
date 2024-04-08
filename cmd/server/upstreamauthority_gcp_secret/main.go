package main

import (
	"github.com/jsiebens/spire-gcpsecret-plugin/pkg/server/plugin/upstreamauthority/gcpsecret"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	plugin := gcpsecret.New()
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
