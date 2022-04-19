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
		Keywords: []string{"AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"},
	},
	{
		ID:       "github-pat",
		Category: CategoryGitHub,
		Title:    "GitHub Personal Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Keywords: []string{"ghp_"},
	},
	{
		ID:       "github-oauth",
		Category: CategoryGitHub,
		Title:    "GitHub OAuth Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Keywords: []string{"gho_"},
	},
	{
		ID:       "github-app-token",
		Category: CategoryGitHub,
		Title:    "GitHub App Token",
		Regex:    MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
		Keywords: []string{"ghu_", "ghs_"},
	},
	{
		ID:       "github-refresh-token",
		Category: CategoryGitHub,
		Title:    "GitHub Refresh Token",
		Regex:    MustCompile(`ghr_[0-9a-zA-Z]{76}`),
		Keywords: []string{"ghr_"},
	},
	{
		ID:       "gitlab-pat",
		Category: CategoryGitLab,
		Title:    "GitLab Personal Access Token",
		Regex:    MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords: []string{"glpat-"},
	},
	{
		ID:       "private-key",
		Category: CategoryAsymmetricPrivateKey,
		Title:    "Asymmetric Private Key",
		Regex:    MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY( BLOCK)?\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY( BLOCK)?\s*?-----`),
		Keywords: []string{"-----"},
	},
	{
		ID:       "shopify-token",
		Category: CategoryShopify,
		Title:    "Shopify token",
		Regex:    MustCompile(`shp(ss|at|ca|pa)_[a-fA-F0-9]{32}`),
		Keywords: []string{"shpss_", "shpat_", "shpca_", "shppa_"},
	},
	{
		ID:       "slack-access-token",
		Category: CategorySlack,
		Title:    "Slack token",
		Regex:    MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`),
		Keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
	},

	{
		ID:       "stripe-access-token",
		Category: CategoryStripe,
		Title:    "Stripe",
		Regex:    MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`),
		Keywords: []string{"sk_test_", "sk_live_", "pk_test_", "pk_live_"},
	},
	{
		ID:       "pypi-upload-token",
		Category: CategoryPyPI,
		Title:    "PyPI upload token",
		Regex:    MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
		Keywords: []string{"pypi-AgEIcHlwaS5vcmc"},
	},
	{
		ID:       "gcp-service-account",
		Category: CategoryGoogle,
		Title:    "Google (GCP) Service-account",
		Regex:    MustCompile(`\"type\": \"service_account\"`),
		Keywords: []string{"\"type\": \"service_account\""},
	},
	{
		ID:              "heroku-api-key",
		Category:        CategoryHeroku,
		Title:           "Heroku API Key",
		Regex:           MustCompile(` (?i)(?P<key>heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"heroku"},
	},
	{
		ID:       "slack-web-hook",
		Category: CategorySlack,
		Title:    "Slack Webhook",
		Regex:    MustCompile(`https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,46}`),
		Keywords: []string{"hooks.slack.com"},
	},
	{
		ID:       "twilio-api-key",
		Category: CategoryTwilio,
		Title:    "Twilio API Key",
		Regex:    MustCompile(`SK[0-9a-fA-F]{32}`),
		Keywords: []string{"SK"},
	},
	{
		ID:       "age-secret-key",
		Category: CategoryAge,
		Title:    "Age secret key",
		Regex:    MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
		Keywords: []string{"AGE-SECRET-KEY-1"},
	},
	{
		ID:              "facebook-token",
		Category:        CategoryFacebook,
		Title:           "Facebook token",
		Regex:           MustCompile(`(?i)(?P<key>facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"facebook"},
	},
	{
		ID:              "twitter-token",
		Category:        CategoryTwitter,
		Title:           "Twitter token",
		Regex:           MustCompile(`(?i)(?P<key>twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{35,44})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"twitter"},
	},
	{
		ID:              "adobe-client-id",
		Category:        CategoryAdobe,
		Title:           "Adobe Client ID (Oauth Web)",
		Regex:           MustCompile(`(?i)(?P<key>adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"adobe"},
	},
	{
		ID:       "adobe-client-secret",
		Category: CategoryAdobe,
		Title:    "Adobe Client Secret",
		Regex:    MustCompile(`(p8e-)(?i)[a-z0-9]{32}`),
		Keywords: []string{"p8e-"},
	},
	{
		ID:       "alibaba-access-key-id",
		Category: CategoryAlibaba,
		Title:    "Alibaba AccessKey ID",
		Regex:    MustCompile(`(LTAI)(?i)[a-z0-9]{20}`),
		Keywords: []string{"LTAI"},
	},
	{
		ID:              "alibaba-secret-key",
		Category:        CategoryAlibaba,
		Title:           "Alibaba Secret Key",
		Regex:           MustCompile(`(?i)(?P<key>alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"alibaba"},
	},
	{
		ID:              "asana-client-id",
		Category:        CategoryAsana,
		Title:           "Asana Client ID",
		Regex:           MustCompile(`(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{16})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"asana"},
	},
	{
		ID:              "asana-client-secret",
		Category:        CategoryAsana,
		Title:           "Asana Client Secret",
		Regex:           MustCompile(`(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"asana"},
	},
	{
		ID:              "atlassian-api-token",
		Category:        CategoryAtlassian,
		Title:           "Atlassian API token",
		Regex:           MustCompile(`(?i)(?P<key>atlassian[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{24})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"atlassian"},
	},
	{
		ID:              "bitbucket-client-id",
		Category:        CategoryBitbucket,
		Title:           "Bitbucket client ID",
		Regex:           MustCompile(`(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"bitbucket"},
	},
	{
		ID:              "bitbucket-client-secret",
		Category:        CategoryBitbucket,
		Title:           "Bitbucket client secret",
		Regex:           MustCompile(`(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9_\-]{64})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"bitbucket"},
	},
	{
		ID:              "beamer-api-token",
		Category:        CategoryBeamer,
		Title:           "Beamer API token",
		Regex:           MustCompile(`(?i)(?P<key>beamer[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>b_[a-z0-9=_\-]{44})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"beamer"},
	},
	{
		ID:       "clojars-api-token",
		Category: CategoryClojars,
		Title:    "Clojars API token",
		Regex:    MustCompile(`(CLOJARS_)(?i)[a-z0-9]{60}`),
		Keywords: []string{"CLOJARS_"},
	},
	{
		ID:              "contentful-delivery-api-token",
		Category:        CategoryContentfulDelivery,
		Title:           "Contentful delivery API token",
		Regex:           MustCompile(`(?i)(?P<key>contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{43})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"contentful"},
	},
	{
		ID:       "databricks-api-token",
		Category: CategoryDatabricks,
		Title:    "Databricks API token",
		Regex:    MustCompile(`dapi[a-h0-9]{32}`),
		Keywords: []string{"dapi"},
	},
	{
		ID:              "discord-api-token",
		Category:        CategoryDiscord,
		Title:           "Discord API key",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{64})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"discord"},
	},
	{
		ID:              "discord-client-id",
		Category:        CategoryDiscord,
		Title:           "Discord client ID",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{18})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"discord"},
	},
	{
		ID:              "discord-client-secret",
		Category:        CategoryDiscord,
		Title:           "Discord client secret",
		Regex:           MustCompile(`(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_\-]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"discord"},
	},
	{
		ID:       "doppler-api-token",
		Category: CategoryDoppler,
		Title:    "Doppler API token",
		Regex:    MustCompile(`['\"](dp\.pt\.)(?i)[a-z0-9]{43}['\"]`),
		Keywords: []string{"dp.pt."},
	},
	{
		ID:       "dropbox-api-secret",
		Category: CategoryDropbox,
		Title:    "Dropbox API secret/key",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]`),
		Keywords: []string{"dropbox"},
	},
	{
		ID:       "dropbox-short-lived-api-token",
		Category: CategoryDropbox,
		Title:    "Dropbox short lived API token",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9\-=_]{135})['\"]`),
		Keywords: []string{"dropbox"},
	},
	{
		ID:       "dropbox-long-lived-api-token",
		Category: CategoryDropbox,
		Title:    "Dropbox long lived API token",
		Regex:    MustCompile(`(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}['\"]`),
		Keywords: []string{"dropbox"},
	},
	{
		ID:       "duffel-api-token",
		Category: CategoryDuffel,
		Title:    "Duffel API token",
		Regex:    MustCompile(`['\"]duffel_(test|live)_(?i)[a-z0-9_-]{43}['\"]`),
		Keywords: []string{"duffel_test_", "duffel_live_"},
	},
	{
		ID:       "dynatrace-api-token",
		Category: CategoryDynatrace,
		Title:    "Dynatrace API token",
		Regex:    MustCompile(`['\"]dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}['\"]`),
		Keywords: []string{"dt0c01."},
	},
	{
		ID:       "easypost-api-token",
		Category: CategoryEasypost,
		Title:    "EasyPost API token",
		Regex:    MustCompile(`['\"]EZ[AT]K(?i)[a-z0-9]{54}['\"]`),
		Keywords: []string{"EZAK", "EZAT"},
	},
	{
		ID:              "fastly-api-token",
		Category:        CategoryFastly,
		Title:           "Fastly API token",
		Regex:           MustCompile(`(?i)(?P<key>fastly[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"fastly"},
	},
	{
		ID:              "finicity-client-secret",
		Category:        CategoryFinicity,
		Title:           "Finicity client secret",
		Regex:           MustCompile(`(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{20})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"finicity"},
	},
	{
		ID:              "finicity-api-token",
		Category:        CategoryFinicity,
		Title:           "Finicity API token",
		Regex:           MustCompile(`(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"finicity"},
	},
	{
		ID:       "flutterwave-public-key",
		Category: CategoryFlutterwave,
		Title:    "Flutterwave public/secret key",
		Regex:    MustCompile(`FLW(PUB|SEC)K_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords: []string{"FLWSECK_TEST-", "FLWPUBK_TEST-"},
	},
	{
		ID:       "flutterwave-enc-key",
		Category: CategoryFlutterwave,
		Title:    "Flutterwave encrypted key",
		Regex:    MustCompile(`FLWSECK_TEST[a-h0-9]{12}`),
		Keywords: []string{"FLWSECK_TEST"},
	},
	{
		ID:       "frameio-api-token",
		Category: CategoryFrameio,
		Title:    "Frame.io API token",
		Regex:    MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`),
		Keywords: []string{"fio-u-"},
	},
	{
		ID:       "gocardless-api-token",
		Category: CategoryGoCardless,
		Title:    "GoCardless API token",
		Regex:    MustCompile(`['\"]live_(?i)[a-z0-9\-_=]{40}['\"]`),
		Keywords: []string{"live_"},
	},
	{
		ID:       "grafana-api-token",
		Category: CategoryGrafana,
		Title:    "Grafana API token",
		Regex:    MustCompile(`['\"]eyJrIjoi(?i)[a-z0-9\-_=]{72,92}['\"]`),
		Keywords: []string{"eyJrIjoi"},
	},
	{
		ID:       "hashicorp-tf-api-token",
		Category: CategoryHashiCorp,
		Title:    "HashiCorp Terraform user/org API token",
		Regex:    MustCompile(`['\"](?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}['\"]`),
		Keywords: []string{"atlasv1."},
	},
	{
		ID:              "hubspot-api-token",
		Title:           "HubSpot API token",
		Category:        CategoryHubSpot,
		Regex:           MustCompile(`(?i)(?P<key>hubspot[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"hubspot"},
	},
	{
		ID:              "intercom-api-token",
		Category:        CategoryIntercom,
		Title:           "Intercom API token",
		Regex:           MustCompile(`(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_]{60})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"intercom"},
	},
	{
		ID:              "intercom-client-secret",
		Category:        CategoryIntercom,
		Title:           "Intercom client secret/ID",
		Regex:           MustCompile(`(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"intercom"},
	},
	{
		ID:       "ionic-api-token",
		Category: CategoryIonic,
		Title:    "Ionic API token",
		Regex:    MustCompile(`(?i)(ionic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](ion_[a-z0-9]{42})['\"]`),
		Keywords: []string{"ionic"},
	},
	{
		ID:       "linear-api-token",
		Category: CategoryLinear,
		Title:    "Linear API token",
		Regex:    MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Keywords: []string{"lin_api_"},
	},
	{
		ID:              "linear-client-secret",
		Category:        CategoryLinear,
		Title:           "Linear client secret/ID",
		Regex:           MustCompile(`(?i)(?P<key>linear[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"linear"},
	},
	{
		ID:              "lob-api-key",
		Category:        CategoryLob,
		Title:           "Lob API Key",
		Regex:           MustCompile(`(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(live|test)_[a-f0-9]{35})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"lob"},
	},
	{
		ID:              "lob-pub-api-key",
		Category:        CategoryLob,
		Title:           "Lob Publishable API Key",
		Regex:           MustCompile(`(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(test|live)_pub_[a-f0-9]{31})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"lob"},
	},
	{
		ID:              "mailchimp-api-key",
		Category:        CategoryMailchimp,
		Title:           "Mailchimp API key",
		Regex:           MustCompile(`(?i)(?P<key>mailchimp[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32}-us20)['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"mailchimp"},
	},
	{
		ID:              "mailgun-token",
		Category:        CategoryMailgun,
		Title:           "Mailgun private API token",
		Regex:           MustCompile(`(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(pub)?key-[a-f0-9]{32})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"mailgun"},
	},
	{
		ID:              "mailgun-signing-key",
		Category:        CategoryMailgun,
		Title:           "Mailgun webhook signing key",
		Regex:           MustCompile(`(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"mailgun"},
	},
	{
		ID:       "mapbox-api-token",
		Category: CategoryMapbox,
		Title:    "Mapbox API token",
		Regex:    MustCompile(`(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22})`),
		Keywords: []string{"pk."},
	},
	{
		ID:              "messagebird-api-token",
		Category:        CategoryMessageBird,
		Title:           "MessageBird API token",
		Regex:           MustCompile(`(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{25})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"messagebird"},
	},
	{
		ID:              "messagebird-client-id",
		Category:        CategoryMessageBird,
		Title:           "MessageBird API client ID",
		Regex:           MustCompile(`(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"messagebird"},
	},
	{
		ID:       "new-relic-user-api-key",
		Category: CategoryNewRelic,
		Title:    "New Relic user API Key",
		Regex:    MustCompile(`['\"](NRAK-[A-Z0-9]{27})['\"]`),
		Keywords: []string{"NRAK-"},
	},
	{
		ID:              "new-relic-user-api-id",
		Category:        CategoryNewRelic,
		Title:           "New Relic user API ID",
		Regex:           MustCompile(`(?i)(?P<key>newrelic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[A-Z0-9]{64})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"newrelic"},
	},
	{
		ID:       "new-relic-browser-api-token",
		Category: CategoryNewRelic,
		Title:    "New Relic ingest browser API token",
		Regex:    MustCompile(`['\"](NRJS-[a-f0-9]{19})['\"]`),
		Keywords: []string{"NRJS-"},
	},
	{
		ID:       "npm-access-token",
		Category: CategoryNpm,
		Title:    "npm access token",
		Regex:    MustCompile(`['\"](npm_(?i)[a-z0-9]{36})['\"]`),
		Keywords: []string{"npm_"},
	},
	{
		ID:       "planetscale-password",
		Category: CategoryPlanetscale,
		Title:    "PlanetScale password",
		Regex:    MustCompile(`pscale_pw_(?i)[a-z0-9\-_\.]{43}`),
		Keywords: []string{"pscale_pw_"},
	},
	{
		ID:       "planetscale-api-token",
		Category: CategoryPlanetscale,
		Title:    "PlanetScale API token",
		Regex:    MustCompile(`pscale_tkn_(?i)[a-z0-9\-_\.]{43}`),
		Keywords: []string{"pscale_tkn_"},
	},
	{
		ID:       "postman-api-token",
		Category: CategoryPostman,
		Title:    "Postman API token",
		Regex:    MustCompile(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
		Keywords: []string{"PMAK-"},
	},
	{
		ID:       "pulumi-api-token",
		Category: CategoryPulumi,
		Title:    "Pulumi API token",
		Regex:    MustCompile(`pul-[a-f0-9]{40}`),
		Keywords: []string{"pul-"},
	},
	{
		ID:       "rubygems-api-token",
		Category: CategoryRubyGems,
		Title:    "Rubygem API token",
		Regex:    MustCompile(`rubygems_[a-f0-9]{48}`),
		Keywords: []string{"rubygems_"},
	},
	{
		ID:       "sendgrid-api-token",
		Category: CategorySendGrid,
		Title:    "SendGrid API token",
		Regex:    MustCompile(`SG\.(?i)[a-z0-9_\-\.]{66}`),
		Keywords: []string{"SG."},
	},
	{
		ID:       "sendinblue-api-token",
		Category: CategorySendinblue,
		Title:    "Sendinblue API token",
		Regex:    MustCompile(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`),
		Keywords: []string{"xkeysib-"},
	},
	{
		ID:       "shippo-api-token",
		Category: CategoryShippo,
		Title:    "Shippo API token",
		Regex:    MustCompile(`shippo_(live|test)_[a-f0-9]{40}`),
		Keywords: []string{"shippo_live_", "shippo_test_"},
	},
	{
		ID:              "linkedin-client-secret",
		Category:        CategoryLinkedIn,
		Title:           "LinkedIn Client secret",
		Regex:           MustCompile(`(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z]{16})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"linkedin"},
	},
	{
		ID:              "linkedin-client-id",
		Category:        CategoryLinkedIn,
		Title:           "LinkedIn Client ID",
		Regex:           MustCompile(`(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{14})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"linkedin"},
	},
	{
		ID:              "twitch-api-token",
		Category:        CategoryTwitch,
		Title:           "Twitch API token",
		Regex:           MustCompile(`(?i)(?P<key>twitch[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`),
		SecretGroupName: "secret",
		Keywords:        []string{"twitch"},
	},
	{
		ID:              "typeform-api-token",
		Category:        CategoryTypeform,
		Title:           "Typeform API token",
		Regex:           MustCompile(`(?i)(?P<key>typeform[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(?P<secret>tfp_[a-z0-9\-_\.=]{59})`),
		SecretGroupName: "secret",
		Keywords:        []string{"typeform"},
	},
}
var builtinAllowRules = []AllowRule{
	{
		ID:          "vendor",
		Description: "Vendor dirs",
		Path:        MustCompile(`\/vendor\/`),
	},
	{
		ID:          "usr-dirs",
		Description: "System dirs",
		Path:        MustCompile(`^usr\/(?:share|include|lib)\/`),
	},
	{
		ID:          "locale-dir",
		Description: "Locales directory contains locales file",
		Path:        MustCompile(`\/locale\/`),
	},
	{
		ID:          "markdown",
		Description: "Markdown files",
		Path:        MustCompile(`\.md$`),
	},
	{
		ID:          "node.js",
		Description: "Node container images",
		Path:        MustCompile(`^opt\/yarn-v[\d.]+\/`),
	},
	{
		ID:          "golang",
		Description: "Go container images",
		Path:        MustCompile(`^usr\/local\/go\/`),
	},
	{
		ID:          "python",
		Description: "Python container images",
		Path:        MustCompile(`^usr\/local\/lib\/python[\d.]+\/`),
	},
	{
		ID:          "wordpress",
		Description: "Wordpress container images",
		Path:        MustCompile(`^usr\/src\/wordpress\/`),
	},
	{
		ID:          "anaconda-log",
		Description: "Anaconda CI Logs in container images",
		Path:        MustCompile(`^var\/log\/anaconda\/`),
	},
}
