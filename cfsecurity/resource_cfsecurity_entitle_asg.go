package cfsecurity

import (
	"context"
	"fmt"

	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
)

// Deprecated : entitlement will be removed
type cfsecurityEntitleAsgResource struct {
	client *client.Client
	config *clients.Config
}

var _ resource.Resource = &cfsecurityEntitleAsgResource{}
var _ resource.ResourceWithConfigure = &cfsecurityEntitleAsgResource{}
var _ resource.ResourceWithImportState = &cfsecurityEntitleAsgResource{}
var _ resource.ResourceWithValidateConfig = &cfsecurityEntitleAsgResource{}

func NewCFSecurityEntitleAsgResource(config *clients.Config) resource.Resource {
	return &cfsecurityEntitleAsgResource{
		config: config,
	}
}

type cfsecurityEntitleAsgResourceModel struct {
	Id      types.String `tfsdk:"id"`
	Entitle types.Set    `tfsdk:"entitle"`
}

type entitle struct {
	AsgID types.String `tfsdk:"asg_id"`
	OrgID types.String `tfsdk:"org_id"`
}

func (r *cfsecurityEntitleAsgResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entitle_asg"
}

func (r *cfsecurityEntitleAsgResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	clt, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = clt
}

func (r *cfsecurityEntitleAsgResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"entitle": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"asg_id": schema.StringAttribute{
							Description: "The security group guid",
							Required:    true,
						},
						"org_id": schema.StringAttribute{
							Description: "The org guid",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

func (r *cfsecurityEntitleAsgResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan cfsecurityEntitleAsgResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return
	}

	plan.Id = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cfsecurityEntitleAsgResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

}

func (r *cfsecurityEntitleAsgResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state cfsecurityEntitleAsgResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cfsecurityEntitleAsgResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {

}

func (r *cfsecurityEntitleAsgResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cfsecurityEntitleAsgResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var configData cfsecurityEntitleAsgResourceModel

	// Read Terraform configuration from the request into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &configData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var entitlements []entitle
	configData.Entitle.ElementsAs(ctx, &entitlements, false)
	for _, entitlement := range entitlements {
		if entitlement.AsgID.IsNull() || entitlement.OrgID.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("entitle"), "Attribute Error", "\"asg_id\" and \"org_id\" fields must be provided.")
		}
	}
}
