package secret

import (
	"github.com/aquasecurity/fanal/types"
)

var (
	CategoryAWS                  = types.SecretRuleCategory("AWS")
	CategoryGitHub               = types.SecretRuleCategory("GitHub")
	CategoryGitLab               = types.SecretRuleCategory("GitLab")
	CategoryAsymmetricPrivateKey = types.SecretRuleCategory("AsymmetricPrivateKey")
	CategoryShopify              = types.SecretRuleCategory("Shopify")
	CategorySlack                = types.SecretRuleCategory("Slack")
	CategoryGoogle               = types.SecretRuleCategory("Google")
	CategoryStripe               = types.SecretRuleCategory("Stripe")
	CategoryPyPI                 = types.SecretRuleCategory("PyPI")
	CategoryHeroku               = types.SecretRuleCategory("Heroku")
	CategoryTwilio               = types.SecretRuleCategory("Twilio")
	CategoryAge                  = types.SecretRuleCategory("Age")
	CategoryFacebook             = types.SecretRuleCategory("Facebook")
	CategoryTwitter              = types.SecretRuleCategory("Twitter")
	CategoryAdobe                = types.SecretRuleCategory("Adobe")
	CategoryAlibaba              = types.SecretRuleCategory("Alibaba")
	CategoryAsana                = types.SecretRuleCategory("Asana")
	CategoryAtlassian            = types.SecretRuleCategory("Atlassian")
	CategoryBitbucket            = types.SecretRuleCategory("Bitbucket")
	CategoryBeamer               = types.SecretRuleCategory("Beamer")
	CategoryClojars              = types.SecretRuleCategory("Clojars")
	CategoryContentfulDelivery   = types.SecretRuleCategory("ContentfulDelivery")
	CategoryDatabricks           = types.SecretRuleCategory("Databricks")
	CategoryDiscord              = types.SecretRuleCategory("Discord")
	CategoryDoppler              = types.SecretRuleCategory("Doppler")
	CategoryDropbox              = types.SecretRuleCategory("Dropbox")
	CategoryDuffel               = types.SecretRuleCategory("Duffel")
	CategoryDynatrace            = types.SecretRuleCategory("Dynatrace")
	CategoryEasypost             = types.SecretRuleCategory("Easypost")
	CategoryFastly               = types.SecretRuleCategory("Fastly")
	CategoryFinicity             = types.SecretRuleCategory("Finicity")
	CategoryFlutterwave          = types.SecretRuleCategory("Flutterwave")
	CategoryFrameio              = types.SecretRuleCategory("Frameio")
	CategoryGoCardless           = types.SecretRuleCategory("GoCardless")
	CategoryGrafana              = types.SecretRuleCategory("Grafana")
	CategoryHashiCorp            = types.SecretRuleCategory("HashiCorp")
	CategoryHubSpot              = types.SecretRuleCategory("HubSpot")
	CategoryIntercom             = types.SecretRuleCategory("Intercom")
	CategoryIonic                = types.SecretRuleCategory("Ionic")
	CategoryLinear               = types.SecretRuleCategory("Linear")
	CategoryLob                  = types.SecretRuleCategory("Lob")
	CategoryMailchimp            = types.SecretRuleCategory("Mailchimp")
	CategoryMailgun              = types.SecretRuleCategory("Mailgun")
	CategoryMapbox               = types.SecretRuleCategory("Mapbox")
	CategoryMessageBird          = types.SecretRuleCategory("MessageBird")
	CategoryNewRelic             = types.SecretRuleCategory("NewRelic")
	CategoryNpm                  = types.SecretRuleCategory("Npm")
	CategoryPlanetscale          = types.SecretRuleCategory("Planetscale")
	CategoryPostman              = types.SecretRuleCategory("Postman")
	CategoryPulumi               = types.SecretRuleCategory("Pulumi")
	CategoryRubyGems             = types.SecretRuleCategory("RubyGems")
	CategorySendGrid             = types.SecretRuleCategory("SendGrid")
	CategorySendinblue           = types.SecretRuleCategory("Sendinblue")
	CategoryShippo               = types.SecretRuleCategory("Shippo")
	CategoryLinkedIn             = types.SecretRuleCategory("LinkedIn")
	CategoryTwitch               = types.SecretRuleCategory("Twitch")
	CategoryTypeform             = types.SecretRuleCategory("Typeform")
)

var builtinRules = []Rule{
	{
		ID:       "aws-access-key-id",
		Category: CategoryAWS,
		Severity: "CRITICAL",
		Title:    "AWS Access Key ID",
		Regex:    MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	},
	{
		ID:       "github-pat",
		Category: CategoryGitHub,
		Title:    "GitHub Personal Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	},
	{
		ID:       "github-oauth",
		Category: CategoryGitHub,
		Title:    "GitHub OAuth Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`gho_[0-9a-zA-Z]{36}`),
	},
	{
		ID:       "github-app-token",
		Category: CategoryGitHub,
		Title:    "GitHub App Token",
		Regex:    MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
	},
	{
		ID:       "github-refresh-token",
		Category: CategoryGitHub,
		Title:    "GitHub Refresh Token",
		Regex:    MustCompile(`ghr_[0-9a-zA-Z]{76}`),
	},
	{
		ID:       "gitlab-pat",
		Category: CategoryGitLab,
		Title:    "GitLab Personal Access Token",
		Regex:    MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
	},
	{
		ID:       "PKCS8-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "PKCS8 private key",
		Regex:    MustCompile(`-----BEGIN PRIVATE KEY-----`),
	},
	{
		ID:       "RSA-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "RSA private key",
		Regex:    MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	},
	{
		ID:       "OPENSSH-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "SSH private key",
		Regex:    MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
	},
	{
		ID:       "PGP-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "PGP private key",
		Regex:    MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	},
	{
		ID:       "SSH-DSA-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "SSH (DSA) private key",
		Regex:    MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	},
	{
		ID:       "SSH-EC-PK",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "SSH (EC) private key",
		Regex:    MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	},
	{
		ID:       "shopify-shared-secret",
		Category: CategoryShopify,
		Title:    "Shopify shared secret",
		Regex:    MustCompile(`shpss_[a-fA-F0-9]{32}`),
	},
	{
		ID:       "shopify-access-token",
		Category: CategoryShopify,
		Title:    "Shopify access token",
		Regex:    MustCompile(`shpat_[a-fA-F0-9]{32}`),
	},
	{
		ID:       "shopify-custom-access-token",
		Category: CategoryShopify,
		Title:    "Shopify custom app access token",
		Regex:    MustCompile(`shpca_[a-fA-F0-9]{32}`),
	},
	{
		ID:       "shopify-private-app-access-token",
		Category: CategoryShopify,
		Title:    "Shopify private app access token",
		Regex:    MustCompile(`shppa_[a-fA-F0-9]{32}`),
	},
	{
		ID:       "slack-access-token",
		Category: CategorySlack,
		Title:    "Slack token",
		Regex:    MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`),
	},

	{
		ID:       "stripe-access-token",
		Category: CategoryStripe,
		Title:    "Stripe",
		Regex:    MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`),
	},
	{
		ID:       "pypi-upload-token",
		Category: CategoryPyPI,
		Title:    "PyPI upload token",
		Regex:    MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
	},
	{
		ID:       "gcp-service-account",
		Category: CategoryGoogle,
		Title:    "Google (GCP) Service-account",
		Regex:    MustCompile(`\"type\": \"service_account\"`),
	},
	{
		ID:              "heroku-api-key",
		Category:        CategoryHeroku,
		Title:           "Heroku API Key",
		Regex:           MustCompile(` (?i)(?P<key>heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "slack-web-hook",
		Category: CategorySlack,
		Title:    "Slack Webhook",
		Regex:    MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`),
	},
	{
		ID:       "twilio-api-key",
		Category: CategoryTwilio,
		Title:    "Twilio API Key",
		Regex:    MustCompile(`SK[0-9a-fA-F]{32}`),
	},
	{
		ID:       "age-secret-key",
		Category: CategoryAge,
		Title:    "Age secret key",
		Regex:    MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
	},
	{
		ID:              "facebook-token",
		Category:        CategoryFacebook,
		Title:           "Facebook token",
		Regex:           MustCompile(`(?i)(?P<key>facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "twitter-token",
		Category:        CategoryTwitter,
		Title:           "Twitter token",
		Regex:           MustCompile(`(?i)(?P<key>twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{35,44})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "adobe-client-id",
		Category:        CategoryAdobe,
		Title:           "Adobe Client ID (Oauth Web)",
		Regex:           MustCompile(`(?i)(?P<key>adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "adobe-client-secret",
		Category: CategoryAdobe,
		Title:    "Adobe Client Secret",
		Regex:    MustCompile(`(p8e-)(?i)[a-z0-9]{32}`),
	},
	{
		ID:       "alibaba-access-key-id",
		Category: CategoryAlibaba,
		Title:    "Alibaba AccessKey ID",
		Regex:    MustCompile(`(LTAI)(?i)[a-z0-9]{20}`),
	},
	{
		ID:              "alibaba-secret-key",
		Category:        CategoryAlibaba,
		Title:           "Alibaba Secret Key",
		Regex:           MustCompile(`(?i)(?P<key>alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "asana-client-id",
		Category:        CategoryAsana,
		Title:           "Asana Client ID",
		Regex:           MustCompile(`(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{16})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "asana-client-secret",
		Category:        CategoryAsana,
		Title:           "Asana Client Secret",
		Regex:           MustCompile(`(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "atlassian-api-token",
		Category:        CategoryAtlassian,
		Title:           "Atlassian API token",
		Regex:           MustCompile(`(?i)(?P<key>atlassian[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{24})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "bitbucket-client-id",
		Category:        CategoryBitbucket,
		Title:           "Bitbucket client ID",
		Regex:           MustCompile(`(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "bitbucket-client-secret",
		Category:        CategoryBitbucket,
		Title:           "Bitbucket client secret",
		Regex:           MustCompile(`(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9_\-]{64})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "beamer-api-token",
		Category:        CategoryBeamer,
		Title:           "Beamer API token",
		Regex:           MustCompile(`(?i)(?P<key>beamer[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>b_[a-z0-9=_\-]{44})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "clojars-api-token",
		Category: CategoryClojars,
		Title:    "Clojars API token",
		Regex:    MustCompile(`(CLOJARS_)(?i)[a-z0-9]{60}`),
	},
	{
		ID:              "contentful-delivery-api-token",
		Category:        CategoryContentfulDelivery,
		Title:           "Contentful delivery API token",
		Regex:           MustCompile(`(?i)(?P<key>contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{43})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "databricks-api-token",
		Category: CategoryDatabricks,
		Title:    "Databricks API token",
		Regex:    MustCompile(`dapi[a-h0-9]{32}`),
	},
	{
		ID:              "discord-api-token",
		Category:        CategoryDiscord,
		Title:           "Discord API key",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{64})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "discord-client-id",
		Category:        CategoryDiscord,
		Title:           "Discord client ID",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{18})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "discord-client-secret",
		Category:        CategoryDiscord,
		Title:           "Discord client secret",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_\-]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "doppler-api-token",
		Category: CategoryDoppler,
		Title:    "Doppler API token",
		Regex:    MustCompile(`['\"](dp\.pt\.)(?i)[a-z0-9]{43}['\"]`),
	},
	{
		ID:       "dropbox-api-secret",
		Category: CategoryDropbox,
		Title:    "Dropbox API secret/key",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]`),
	},
	{
		ID:       "dropbox--api-key",
		Category: CategoryDropbox,
		Title:    "Dropbox API secret/key",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]`),
	},
	{
		ID:       "dropbox-short-lived-api-token",
		Category: CategoryDropbox,
		Title:    "Dropbox short lived API token",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9\-=_]{135})['\"]`),
	},
	{
		ID:       "dropbox-long-lived-api-token",
		Category: CategoryDropbox,
		Title:    "Dropbox long lived API token",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}['\"]`),
	},
	{
		ID:       "duffel-api-token",
		Category: CategoryDuffel,
		Title:    "Duffel API token",
		Regex:    MustCompile(`['\"]duffel_(test|live)_(?i)[a-z0-9_-]{43}['\"]`),
	},
	{
		ID:       "dynatrace-api-token",
		Category: CategoryDynatrace,
		Title:    "Dynatrace API token",
		Regex:    MustCompile(`['\"]dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}['\"]`),
	},
	{
		ID:       "easypost-api-token",
		Category: CategoryEasypost,
		Title:    "EasyPost API token",
		Regex:    MustCompile(`['\"]EZAK(?i)[a-z0-9]{54}['\"]`),
	},
	{
		ID:       "easypost-test-api-token",
		Category: CategoryEasypost,
		Title:    "EasyPost test API token",
		Regex:    MustCompile(`['\"]EZTK(?i)[a-z0-9]{54}['\"]`),
	},
	{
		ID:              "fastly-api-token",
		Category:        CategoryFastly,
		Title:           "Fastly API token",
		Regex:           MustCompile(`(?i)(?P<key>fastly[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "finicity-client-secret",
		Category:        CategoryFinicity,
		Title:           "Finicity client secret",
		Regex:           MustCompile(`(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{20})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "finicity-api-token",
		Category:        CategoryFinicity,
		Title:           "Finicity API token",
		Regex:           MustCompile(`(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "flutterwave-public-key",
		Category: CategoryFlutterwave,
		Title:    "Flutterwave public key",
		Regex:    MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`),
	},
	{
		ID:       "flutterwave-secret-key",
		Category: CategoryFlutterwave,
		Title:    "Flutterwave secret key",
		Regex:    MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
	},
	{
		ID:       "flutterwave-enc-key",
		Category: CategoryFlutterwave,
		Title:    "Flutterwave encrypted key",
		Regex:    MustCompile(`FLWSECK_TEST[a-h0-9]{12}`),
	},
	{
		ID:       "frameio-api-token",
		Category: CategoryFrameio,
		Title:    "Frame.io API token",
		Regex:    MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`),
	},
	{
		ID:       "gocardless-api-token",
		Category: CategoryGoCardless,
		Title:    "GoCardless API token",
		Regex:    MustCompile(`['\"]live_(?i)[a-z0-9\-_=]{40}['\"]`),
	},
	{
		ID:       "grafana-api-token",
		Category: CategoryGrafana,
		Title:    "Grafana API token",
		Regex:    MustCompile(`['\"]eyJrIjoi(?i)[a-z0-9\-_=]{72,92}['\"]`),
	},
	{
		ID:       "hashicorp-tf-api-token",
		Category: CategoryHashiCorp,
		Title:    "HashiCorp Terraform user/org API token",
		Regex:    MustCompile(`['\"](?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}['\"]`),
	},
	{
		ID:              "hubspot-api-token",
		Title:           "HubSpot API token",
		Category:        CategoryHubSpot,
		Regex:           MustCompile(`(?i)(?P<key>hubspot[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "intercom-api-token",
		Category:        CategoryIntercom,
		Title:           "Intercom API token",
		Regex:           MustCompile(`(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_]{60})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "intercom-client-secret",
		Category:        CategoryIntercom,
		Title:           "Intercom client secret/ID",
		Regex:           MustCompile(`(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "ionic-api-token",
		Category: CategoryIonic,
		Title:    "Ionic API token",
		Regex:    MustCompile(`(?i)(ionic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](ion_[a-z0-9]{42})['\"]`),
	},
	{
		ID:       "linear-api-token",
		Category: CategoryLinear,
		Title:    "Linear API token",
		Regex:    MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
	},
	{
		ID:              "linear-client-secret",
		Category:        CategoryLinear,
		Title:           "Linear client secret/ID",
		Regex:           MustCompile(`(?i)(?P<key>linear[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "lob-api-key",
		Category:        CategoryLob,
		Title:           "Lob API Key",
		Regex:           MustCompile(`(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(live|test)_[a-f0-9]{35})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "lob-pub-api-key",
		Category:        CategoryLob,
		Title:           "Lob Publishable API Key",
		Regex:           MustCompile(`(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(test|live)_pub_[a-f0-9]{31})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "mailchimp-api-key",
		Category:        CategoryMailchimp,
		Title:           "Mailchimp API key",
		Regex:           MustCompile(`(?i)(?P<key>mailchimp[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32}-us20)['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "mailgun-private-api-token",
		Category:        CategoryMailgun,
		Title:           "Mailgun private API token",
		Regex:           MustCompile(`(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>key-[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "mailgun-pub-key",
		Category:        CategoryMailgun,
		Title:           "Mailgun public validation key",
		Regex:           MustCompile(`(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>pubkey-[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "mailgun-signing-key",
		Category:        CategoryMailgun,
		Title:           "Mailgun webhook signing key",
		Regex:           MustCompile(`(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "mapbox-api-token",
		Category: CategoryMapbox,
		Title:    "Mapbox API token",
		Regex:    MustCompile(`(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22})`),
	},
	{
		ID:              "messagebird-api-token",
		Category:        CategoryMessageBird,
		Title:           "MessageBird API token",
		Regex:           MustCompile(`(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{25})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "messagebird-client-id",
		Category:        CategoryMessageBird,
		Title:           "MessageBird API client ID",
		Regex:           MustCompile(`(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "new-relic-user-api-key",
		Category: CategoryNewRelic,
		Title:    "New Relic user API Key",
		Regex:    MustCompile(`['\"](NRAK-[A-Z0-9]{27})['\"]`),
	},
	{
		ID:              "new-relic-user-api-id",
		Category:        CategoryNewRelic,
		Title:           "New Relic user API ID",
		Regex:           MustCompile(`(?i)(?P<key>newrelic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[A-Z0-9]{64})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:       "new-relic-browser-api-token",
		Category: CategoryNewRelic,
		Title:    "New Relic ingest browser API token",
		Regex:    MustCompile(`['\"](NRJS-[a-f0-9]{19})['\"]`),
	},
	{
		ID:       "npm-access-token",
		Category: CategoryNpm,
		Title:    "npm access token",
		Regex:    MustCompile(`['\"](npm_(?i)[a-z0-9]{36})['\"]`),
	},
	{
		ID:       "planetscale-password",
		Category: CategoryPlanetscale,
		Title:    "PlanetScale password",
		Regex:    MustCompile(`pscale_pw_(?i)[a-z0-9\-_\.]{43}`),
	},
	{
		ID:       "planetscale-api-token",
		Category: CategoryPlanetscale,
		Title:    "PlanetScale API token",
		Regex:    MustCompile(`pscale_tkn_(?i)[a-z0-9\-_\.]{43}`),
	},
	{
		ID:       "postman-api-token",
		Category: CategoryPostman,
		Title:    "Postman API token",
		Regex:    MustCompile(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
	},
	{
		ID:       "pulumi-api-token",
		Category: CategoryPulumi,
		Title:    "Pulumi API token",
		Regex:    MustCompile(`pul-[a-f0-9]{40}`),
	},
	{
		ID:       "rubygems-api-token",
		Category: CategoryRubyGems,
		Title:    "Rubygem API token",
		Regex:    MustCompile(`rubygems_[a-f0-9]{48}`),
	},
	{
		ID:       "sendgrid-api-token",
		Category: CategorySendGrid,
		Title:    "SendGrid API token",
		Regex:    MustCompile(`SG\.(?i)[a-z0-9_\-\.]{66}`),
	},
	{
		ID:       "sendinblue-api-token",
		Category: CategorySendinblue,
		Title:    "Sendinblue API token",
		Regex:    MustCompile(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`),
	},
	{
		ID:       "shippo-api-token",
		Category: CategoryShippo,
		Title:    "Shippo API token",
		Regex:    MustCompile(`shippo_(live|test)_[a-f0-9]{40}`),
	},
	{
		ID:              "linkedin-client-secret",
		Category:        CategoryLinkedIn,
		Title:           "LinkedIn Client secret",
		Regex:           MustCompile(`(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z]{16})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "linkedin-client-id",
		Category:        CategoryLinkedIn,
		Title:           "LinkedIn Client ID",
		Regex:           MustCompile(`(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{14})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "twitch-api-token",
		Category:        CategoryTwitch,
		Title:           "Twitch API token",
		Regex:           MustCompile(`(?i)(?P<key>twitch[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`),
		SecretGroupName: "secret",
	},
	{
		ID:              "typeform-api-token",
		Category:        CategoryTypeform,
		Title:           "Typeform API token",
		Regex:           MustCompile(`(?i)(?P<key>typeform[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(?P<secret>tfp_[a-z0-9\-_\.=]{59})`),
		SecretGroupName: "secret",
	},
}
