// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fromproto6

import (
	"context"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/internal/fwschema"
	"github.com/hashicorp/terraform-plugin-framework/internal/fwserver"
	"github.com/hashicorp/terraform-plugin-framework/internal/privatestate"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ReadResourceRequest returns the *fwserver.ReadResourceRequest
// equivalent of a *tfprotov6.ReadResourceRequest.
func ReadResourceRequest(ctx context.Context, proto6 *tfprotov6.ReadResourceRequest, reqResource resource.Resource, resourceSchema fwschema.Schema, providerMetaSchema fwschema.Schema, resourceBehavior resource.ResourceBehavior, identitySchema fwschema.Schema) (*fwserver.ReadResourceRequest, diag.Diagnostics) {
	if proto6 == nil {
		return nil, nil
	}

	var diags diag.Diagnostics

	fw := &fwserver.ReadResourceRequest{
		Resource:           reqResource,
		ResourceBehavior:   resourceBehavior,
		IdentitySchema:     identitySchema,
		ClientCapabilities: ReadResourceClientCapabilities(proto6.ClientCapabilities),
	}

	currentState, currentStateDiags := State(ctx, proto6.CurrentState, resourceSchema)

	diags.Append(currentStateDiags...)

	fw.CurrentState = currentState

	currentIdentity, currentIdentityDiags := ResourceIdentity(ctx, proto6.CurrentIdentity, identitySchema)

	diags.Append(currentIdentityDiags...)

	fw.CurrentIdentity = currentIdentity

	providerMeta, providerMetaDiags := ProviderMeta(ctx, proto6.ProviderMeta, providerMetaSchema)

	diags.Append(providerMetaDiags...)

	fw.ProviderMeta = providerMeta

	privateData, privateDataDiags := privatestate.NewData(ctx, proto6.Private)

	diags.Append(privateDataDiags...)

	fw.Private = privateData

	return fw, diags
}
