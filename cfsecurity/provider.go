package cfsecurity

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
)

var _ provider.Provider = &CFSecurityProvider{}

type CFSecurityProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
	config  *clients.Config
}

type CFSecurityProviderModel struct {
	client            *client.Client
	Endpoint          types.String `tfsdk:"cf_api_url"`
	CFSecurityUrl     types.String `tfsdk:"cf_security_url"`
	User              types.String `tfsdk:"user"`
	Password          types.String `tfsdk:"password"`
	CFClientID        types.String `tfsdk:"cf_client_id"`
	CFClientSecret    types.String `tfsdk:"cf_client_secret"`
	SkipSslValidation types.Bool   `tfsdk:"skip_ssl_validation"`
}

func (m CFSecurityProviderModel) valid() (bool, CFSecurityProviderModel) {
	// Check environment variables
	if m.Endpoint.ValueString() == "" {
		m.Endpoint = types.StringValue(os.Getenv("CF_API_URL"))
	}
	if m.CFSecurityUrl.ValueString() == "" {
		m.CFSecurityUrl = types.StringValue(os.Getenv("CF_SECURITY_URL"))
	}
	if m.User.ValueString() == "" {
		m.User = types.StringValue(os.Getenv("CF_USER"))
	}
	if m.Password.ValueString() == "" {
		m.Password = types.StringValue(os.Getenv("CF_PASSWORD"))
	}
	if m.CFClientID.ValueString() == "" {
		m.CFClientID = types.StringValue(os.Getenv("CF_CLIENT_ID"))
	}
	if m.CFClientSecret.ValueString() == "" {
		m.CFClientSecret = types.StringValue(os.Getenv("CF_CLIENT_SECRET"))
	}
	if m.SkipSslValidation.IsNull() {
		val, _ := strconv.ParseBool(os.Getenv("CF_SKIP_SSL_VALIDATION"))
		m.SkipSslValidation = types.BoolValue(val)
	}

	return m.User.ValueString() != "" &&
		m.Password.ValueString() != "" &&
		m.Endpoint.ValueString() != "", m

}

func (p *CFSecurityProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cfsecurity"
	resp.Version = p.version
}

func (p *CFSecurityProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"cf_api_url": schema.StringAttribute{
				Required: true,
			},
			"cf_security_url": schema.StringAttribute{
				Optional: true,
			},
			"user": schema.StringAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Optional: true,
			},
			"cf_client_id": schema.StringAttribute{
				Optional: true,
			},
			"cf_client_secret": schema.StringAttribute{
				Optional: true,
			},
			"skip_ssl_validation": schema.BoolAttribute{
				Required: true,
			},
		},
	}
}

func (p *CFSecurityProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data CFSecurityProviderModel

	// Read configuration data into model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	isValid, data := data.valid()
	if !isValid {
		resp.Diagnostics.AddError(
			"Client Error: Bad parameter",
			"User, password or endpoint is empty",
		)
		return
	}

	p.config = &clients.Config{
		Endpoint:          data.Endpoint.ValueString(),
		User:              data.User.ValueString(),
		Password:          data.Password.ValueString(),
		CFClientID:        data.CFClientID.ValueString(),
		CFClientSecret:    data.CFClientSecret.ValueString(),
		SkipSslValidation: data.SkipSslValidation.ValueBool(),
	}

	s, err := clients.NewSession(*p.config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error: Authentication failed",
			err.Error(),
		)
		return
	}

	uri, err := url.Parse(p.config.Endpoint)
	if err != nil {
		resp.Diagnostics.AddError(
			"Client Error: Parsing endpoint failed",
			err.Error(),
		)
		return
	}

	pHost := strings.SplitN(uri.Host, ".", 2)
	pHost[0] = "cfsecurity"
	uri.Host = strings.Join(pHost, ".")
	uri.Path = ""

	securityEndpoint := uri.String()
	if data.CFSecurityUrl.ValueString() != "" {
		securityEndpoint = data.CFSecurityUrl.ValueString()
	}

	data.client = client.NewClient(securityEndpoint, s.V3(), s.ConfigStore().AccessToken(), p.config.Endpoint,
		&http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: p.config.SkipSslValidation},
		},
	)
	resp.DataSourceData = data.client
	resp.ResourceData = data.client
}

func (p *CFSecurityProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return NewCFSecurityEntitleAsgResource(p.config) },
		func() resource.Resource { return NewCFSecurityBindResource(p.config) },
	}
}

func (p *CFSecurityProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return NewCFSecurityAsgDataSource(p.config) },
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &CFSecurityProvider{
			version: version,
		}
	}
}

func getExpiresAtFromToken(accessToken string) (time.Time, error) {
	tokenSplit := strings.Split(accessToken, ".")
	if len(tokenSplit) < 3 {
		return time.Now(), fmt.Errorf("not a jwt")
	}

	decodeToken, err := base64.RawStdEncoding.DecodeString(tokenSplit[1])
	if err != nil {
		return time.Now(), err
	}

	token := struct {
		Exp int `json:"exp"`
	}{}

	err = json.Unmarshal(decodeToken, &token)
	if err != nil {
		return time.Now(), err
	}

	expAt := time.Unix(int64(token.Exp), 0)

	// Taking a minute off the timer to have a margin of error
	expAtBefore := expAt.Add(time.Duration(-1) * time.Minute)

	return expAtBefore, nil
}

func refreshTokenIfExpired(client *client.Client, config *clients.Config) error {

	expiresAt, err := getExpiresAtFromToken(*client.GetAccessToken())
	if err != nil {
		return err
	}

	if expiresAt.Before(time.Now()) {
		s, err := clients.NewSession(*config)
		if err != nil {
			return err
		}

		accessToken := s.ConfigStore().AccessToken()
		if err != nil {
			return err
		}
		client.SetAccessToken(accessToken)
		return nil
	}

	return nil
}
