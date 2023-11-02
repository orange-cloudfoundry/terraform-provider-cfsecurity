package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/orange-cloudfoundry/terraform-provider-cfsecurity/cfsecurity"
	"github.com/prometheus/common/version"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/orange-cloudfoundry/cfsecurity",
		Debug:   debugMode,
	}
	err := providerserver.Serve(context.Background(), cfsecurity.New(version.Version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
