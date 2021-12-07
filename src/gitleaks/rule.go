package main

import "fmt"

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getDefaultRecommend(rule string) *recommend {
	return &recommend{
		Risk: fmt.Sprintf(`%s
		- If a key is leaked, a cyber attack is possible within the scope of the key's authority
		- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`, rule),
		Recommendation: `Take the following actions for leaked keys
		- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
		- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
		- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
	}
}

type ruleMetaData struct {
	Score     float32
	Recommend recommend
	// Tag       []string
}

// ruleMap maps meta data by rule name.
// @see Gitleaks default ruleset(description) https://github.com/zricethezav/gitleaks/blob/master/config/default.go
var ruleMap = map[string]ruleMetaData{
	"AWS Access Key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `AWS Access Key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.
			- https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/`,
		},
	},
	"AWS Secret Key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `AWS Secret Key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.
			- https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/`,
		},
	},
	"AWS MWS key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `AWS MWS key(Amazon Marketplace Web Service key)
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.
			- https://docs.developer.amazonservices.com/en_US/dev_guide/DG_IfNew.html`,
		},
	},
	"Google (GCP) Service Account": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Google (GCP) Service Account
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.
			- https://cloud.google.com/iam/docs/creating-managing-service-account-keys#deleting`,
		},
	},
	"Heroku API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Heroku API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.
			- https://devcenter.heroku.com/articles/securekey`,
		},
	},
	"MailChimp API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `MailChimp API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Mailgun API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Mailgun API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"PayPal Braintree access token": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `PayPal Braintree access token
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Picatic API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Picatic API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"SendGrid API Key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `SendGrid API Key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Stripe API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Stripe API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Square access token": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Square access token
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Square OAuth secret": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Square OAuth secret
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Twilio API key": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Twilio API key
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Dynatrace ttoken": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Dynatrace ttoken
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Shopify shared secret": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Shopify shared secret
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Shopify access token": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Shopify access token
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Shopify custom app access token": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Shopify custom app access token
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
	"Shopify private app access token": {
		Score: 0.8,
		Recommend: recommend{
			Risk: `Shopify private app access token
			- If a key is leaked, a cyber attack is possible within the scope of the key's authority
			- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			Recommendation: `Take the following actions for leaked keys
			- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
			- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
			- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
		},
	},
}
