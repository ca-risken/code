package code

import (
	"errors"
	"fmt"
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// Validate ListDataSourceRequest
func (l *ListDataSourceRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.Name, validation.Length(0, 64)),
	)
}

// Validate ListGitleaksRequest
func (l *ListGitleaksRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
	)
}

// Validate ListGitleaksRequest
func (l *GetGitleaksRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
		validation.Field(&l.GitleaksId, validation.Required),
	)
}

// Validate PutGitleaksRequest
func (p *PutGitleaksRequest) Validate() error {
	if p.Gitleaks == nil {
		return errors.New("Required Gitleaks")
	}
	if err := validation.ValidateStruct(p,
		validation.Field(&p.ProjectId, validation.Required, validation.In(p.Gitleaks.ProjectId)),
	); err != nil {
		return err
	}
	return p.Gitleaks.Validate()
}

// Validate DeleteGitleaksRequest
func (d *DeleteGitleaksRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.GitleaksId, validation.Required),
	)
}

// Validate ListEnterpriseOrgRequest
func (l *ListEnterpriseOrgRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.GitleaksId, validation.Required),
		validation.Field(&l.ProjectId, validation.Required),
	)
}

// Validate PutEnterpriseOrgRequest
func (p *PutEnterpriseOrgRequest) Validate() error {
	if p.EnterpriseOrg == nil {
		return errors.New("Required EnterpriseOrg")
	}
	if err := validation.ValidateStruct(p,
		validation.Field(&p.ProjectId, validation.Required, validation.In(p.EnterpriseOrg.ProjectId)),
	); err != nil {
		return err
	}
	return p.EnterpriseOrg.Validate()
}

// Validate DeleteEnterpriseOrgRequest
func (d *DeleteEnterpriseOrgRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.GitleaksId, validation.Required),
		validation.Field(&d.Login, validation.Required),
	)
}

// Validate InvokeScanRequest
func (i *InvokeScanGitleaksRequest) Validate() error {
	return validation.ValidateStruct(i,
		validation.Field(&i.ProjectId, validation.Required),
		validation.Field(&i.GitleaksId, validation.Required),
	)
}

/**
 * Entity
**/

// Validate GitleaksForUpsert
func (g *GitleaksForUpsert) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.CodeDataSourceId, validation.Required),
		validation.Field(&g.Name, validation.Length(0, 64)),
		validation.Field(&g.ProjectId, validation.Required),
		validation.Field(&g.BaseUrl, validation.Length(0, 128), is.URL),
		validation.Field(&g.TargetResource, validation.Required, validation.Length(0, 128)),
		validation.Field(&g.RepositoryPattern, validation.Length(0, 128), validation.By(compilableRegexp(g.RepositoryPattern))),
		validation.Field(&g.GithubUser, validation.Length(0, 64)),
		validation.Field(&g.PersonalAccessToken, validation.Length(0, 255)),
		validation.Field(&g.StatusDetail, validation.Length(0, 255)),
		validation.Field(&g.ScanAt, validation.Min(0), validation.Max(253402268399)),          //  1970-01-01T00:00:00 ~ 9999-12-31T23:59:59
		validation.Field(&g.ScanSucceededAt, validation.Min(0), validation.Max(253402268399)), //  1970-01-01T00:00:00 ~ 9999-12-31T23:59:59
	)
}

// Validate EnterpriseOrgForUpsert
func (e *EnterpriseOrgForUpsert) Validate() error {
	return validation.ValidateStruct(e,
		validation.Field(&e.GitleaksId, validation.Required),
		validation.Field(&e.Login, validation.Required, validation.Length(0, 128)),
		validation.Field(&e.ProjectId, validation.Required),
	)
}

// Check the `ptn`(string) that is compilable regexp pattern
func compilableRegexp(ptn string) validation.RuleFunc {
	return func(value interface{}) error {
		s, _ := value.(string)
		if s != ptn {
			return fmt.Errorf("Unexpected string, got: %+v", ptn)
		}
		if _, err := regexp.Compile(ptn); err != nil {
			return fmt.Errorf("Could not regexp complie, pattern=%s, err=%+v", ptn, err)
		}
		return nil
	}
}
