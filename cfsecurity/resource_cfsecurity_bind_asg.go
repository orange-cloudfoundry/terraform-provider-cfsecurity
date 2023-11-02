package cfsecurity

import (
	"context"
	"fmt"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"

	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/thoas/go-funk"
)

type cfsecurityBindResource struct {
	client *client.Client
	config *clients.Config
}

var _ resource.Resource = &cfsecurityBindResource{}
var _ resource.ResourceWithConfigure = &cfsecurityBindResource{}
var _ resource.ResourceWithImportState = &cfsecurityBindResource{}
var _ resource.ResourceWithValidateConfig = &cfsecurityBindResource{}

func NewCFSecurityBindResource(config *clients.Config) resource.Resource {
	return &cfsecurityBindResource{
		config: config,
	}
}

type cfsecurityBindResourceModel struct {
	Id    types.String `tfsdk:"id"`
	Bind  types.Set    `tfsdk:"bind"`
	Force types.Bool   `tfsdk:"force"`
}

type bind struct {
	AsgID   types.String `tfsdk:"asg_id"`
	SpaceID types.String `tfsdk:"space_id"`
}

func (r *cfsecurityBindResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bind_asg"
}

// Configure enables provider-level data or clients to be set in the
// provider-defined DataSource type. It is separately executed for each
// ReadDataSource RPC.
func (r *cfsecurityBindResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *cfsecurityBindResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"force": schema.BoolAttribute{
				Optional: true,
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"bind": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"asg_id": schema.StringAttribute{
							Description: "The security group guid",
							Required:    true,
						},
						"space_id": schema.StringAttribute{
							Description: "The space guid",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

func (r *cfsecurityBindResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan cfsecurityBindResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := refreshTokenIfExpired(r.client, r.config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error",
			fmt.Sprintf("Unable to refresh token: %s", err),
		)
		return
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error",
			fmt.Sprintf("Unable to generate uuid: %s", err),
		)
		return
	}

	var binds []bind
	resp.Diagnostics.Append(plan.Bind.ElementsAs(ctx, &binds, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, bind := range binds {
		err = r.client.BindSecurityGroup(bind.AsgID.ValueString(), bind.SpaceID.ValueString(), r.client.GetEndpoint())
		if err != nil {
			resp.Diagnostics.AddError(
				"Client Error",
				fmt.Sprintf("Unable to bind security group, got error: %s", err),
			)
			return
		}
	}
	plan.Id = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cfsecurityBindResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state cfsecurityBindResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := refreshTokenIfExpired(r.client, r.config)
	if err != nil {
		return
	}

	secGroups, err := r.client.GetSecGroups([]ccv3.Query{}, 0)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error",
			fmt.Sprintf("Unable to get security groups : %s", err),
		)
		return
	}

	userIsAdmin, _ := r.client.CurrentUserIsAdmin()
	// check if force and if user is not an admin
	if state.Force.ValueBool() && !userIsAdmin {
		finalBinds := make([]bind, 0)
		for i, secGroup := range secGroups.Resources {
			secGroupSpaceBindings := make([]string, 0)
			for _, space := range secGroups.Resources[i].Relationships.Running_Spaces.Data {
				if !funk.ContainsString(secGroupSpaceBindings, space.GUID) {
					secGroupSpaceBindings = append(secGroupSpaceBindings, space.GUID)
				}
			}
			for _, space := range secGroups.Resources[i].Relationships.Staging_Spaces.Data {
				if !funk.ContainsString(secGroupSpaceBindings, space.GUID) {
					secGroupSpaceBindings = append(secGroupSpaceBindings, space.GUID)
				}
			}
			for _, spaceGUID := range secGroupSpaceBindings {
				finalBinds = append(finalBinds, bind{
					AsgID:   types.StringValue(secGroup.GUID),
					SpaceID: types.StringValue(spaceGUID),
				})
			}
		}

		bindType := req.State.Schema.GetBlocks()["bind"].(schema.SetNestedBlock).NestedObject.Type()
		binds, aErr := types.SetValueFrom(ctx, bindType, finalBinds)
		if aErr.HasError() {
			resp.Diagnostics.Append(aErr...)
			return
		}
		state.Bind = binds

		// Save updated data into Terraform state
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	var secGroupsTf []bind
	state.Bind.ElementsAs(ctx, &secGroupsTf, false)

	finalBinds := intersectSlices(secGroupsTf, secGroups.Resources, func(source, item interface{}) bool {
		secGroupTf := source.(bind)
		secGroup := item.(client.SecurityGroup)
		asgIDTf := secGroupTf.AsgID.ValueString()
		spaceIDTf := secGroupTf.SpaceID.ValueString()
		if asgIDTf != secGroup.GUID {
			return false
		}
		spaces, _ := r.client.GetSecGroupSpaces(&secGroup)
		return isInSlice(spaces.Resources, func(object interface{}) bool {
			space := object.(client.Space)
			return space.GUID == spaceIDTf
		})
	})

	bindType := req.State.Schema.GetBlocks()["bind"].(schema.SetNestedBlock).NestedObject.Type()
	binds, aErr := types.SetValueFrom(ctx, bindType, finalBinds)
	if aErr.HasError() {
		resp.Diagnostics.Append(aErr...)
		return
	}
	state.Bind = binds

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cfsecurityBindResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state cfsecurityBindResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := refreshTokenIfExpired(r.client, r.config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error",
			fmt.Sprintf("Unable to refresh token: %s", err),
		)
		return
	}

	var planBinds, stateBinds []bind
	plan.Bind.ElementsAs(ctx, &planBinds, false)
	state.Bind.ElementsAs(ctx, &stateBinds, false)
	remove, add := getListBindChanges(stateBinds, planBinds)

	if len(remove) > 0 {
		for _, rBind := range remove {
			err := r.client.UnBindSecurityGroup(rBind.AsgID.ValueString(), rBind.SpaceID.ValueString(), r.client.GetEndpoint())
			if err != nil && !isNotFoundErr(err) {
				resp.Diagnostics.AddError(
					"Client Error",
					fmt.Sprintf("Unable to unbind security group, got error: %s", err),
				)
				return
			}
		}
	}
	if len(add) > 0 {
		for _, aBind := range add {
			err := r.client.BindSecurityGroup(aBind.AsgID.ValueString(), aBind.SpaceID.ValueString(), r.client.GetEndpoint())
			if err != nil {
				resp.Diagnostics.AddError(
					"Client Error",
					fmt.Sprintf("Unable to bind security group, got error: %s", err),
				)
				return
			}
		}
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cfsecurityBindResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state cfsecurityBindResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := refreshTokenIfExpired(r.client, r.config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error",
			fmt.Sprintf("Unable to refresh token: %s", err),
		)
		return
	}

	var binds []bind
	state.Bind.ElementsAs(ctx, &binds, false)

	for _, bind := range binds {
		err := r.client.UnBindSecurityGroup(bind.AsgID.ValueString(), bind.SpaceID.ValueString(), r.client.GetEndpoint())
		if err != nil && !isNotFoundErr(err) {
			resp.Diagnostics.AddError(
				"Client Error",
				fmt.Sprintf("Unable to unbind security group, got error: %s", err),
			)
			return
		}
	}
}

func (r *cfsecurityBindResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Called during terraform validate through ValidateResourceConfig RPC
// Validates the logic in the application block in the Schema
func (r *cfsecurityBindResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var configData cfsecurityBindResourceModel

	// Read Terraform configuration from the request into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &configData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var binds []bind
	configData.Bind.ElementsAs(ctx, &binds, false)
	for _, bind := range binds {
		if bind.AsgID.IsNull() || bind.SpaceID.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("bind"), "Attribute Error", "\"asg_id\" and \"space_id\" fields must be provided.")
		}
	}
}
