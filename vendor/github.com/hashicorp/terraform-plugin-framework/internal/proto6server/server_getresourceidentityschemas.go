// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proto6server

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/internal/fromproto6"
	"github.com/hashicorp/terraform-plugin-framework/internal/fwserver"
	"github.com/hashicorp/terraform-plugin-framework/internal/logging"
	"github.com/hashicorp/terraform-plugin-framework/internal/toproto6"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// GetResourceIdentitySchemas satisfies the tfprotov6.ProviderServer interface.
func (s *Server) GetResourceIdentitySchemas(ctx context.Context, proto6Req *tfprotov6.GetResourceIdentitySchemasRequest) (*tfprotov6.GetResourceIdentitySchemasResponse, error) {
	ctx = s.registerContext(ctx)
	ctx = logging.InitContext(ctx)

	fwReq := fromproto6.GetResourceIdentitySchemasRequest(ctx, proto6Req)
	fwResp := &fwserver.GetResourceIdentitySchemasResponse{}

	s.FrameworkServer.GetResourceIdentitySchemas(ctx, fwReq, fwResp)

	return toproto6.GetResourceIdentitySchemasResponse(ctx, fwResp), nil
}
