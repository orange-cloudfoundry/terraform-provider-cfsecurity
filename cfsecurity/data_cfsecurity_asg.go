package cfsecurity

import (
	"context"
	"fmt"

	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
)

type cfsecurityAsgDataSource struct {
	client *client.Client
	config *clients.Config
}

var _ datasource.DataSource = &cfsecurityAsgDataSource{}

func NewCFSecurityAsgDataSource(config *clients.Config) datasource.DataSource {
	return &cfsecurityAsgDataSource{
		config: config,
	}
}

type cfsecurityAsgDataSourceModel struct {
	Name types.String `tfsdk:"name"`
	Id   types.String `tfsdk:"id"`
}

func (d *cfsecurityAsgDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_asg"
}

func (d *cfsecurityAsgDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *cfsecurityAsgDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	d.client = clt
}

func (d *cfsecurityAsgDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data cfsecurityAsgDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := refreshTokenIfExpired(d.client, d.config)
	if err != nil {
		return
	}

	secGroup, err := d.client.GetSecGroupByName(data.Name.ValueString())
	if err != nil {
		return
	}

	data.Id = types.StringValue(secGroup.GUID)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
