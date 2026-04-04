package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (a *App) dastAuthTemplateCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "auth-template [type]",
		Short:   a.catalog.T("dast_auth_template_title"),
		Args:    cobra.MaximumNArgs(1),
		Example: a.catalog.T("dast_auth_template_example"),
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := dastAuthTemplateProfiles(args)
			if err != nil {
				return err
			}
			payload := struct {
				Profiles []domain.DastAuthProfile `json:"profiles"`
			}{
				Profiles: profiles,
			}
			body, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
	return command
}

func dastAuthTemplateProfiles(args []string) ([]domain.DastAuthProfile, error) {
	templates := domain.NormalizeDastAuthProfiles([]domain.DastAuthProfile{
		{
			Name:                "staging-bearer",
			Type:                domain.DastAuthBearer,
			SecretEnv:           "STAGING_API_TOKEN",
			SessionCheckURL:     "https://api.example.test/me",
			SessionCheckPattern: "200 OK",
		},
		{
			Name:                "staging-header",
			Type:                domain.DastAuthHeader,
			HeaderName:          "X-API-Key",
			SecretEnv:           "STAGING_API_KEY",
			SessionCheckURL:     "https://api.example.test/me",
			SessionCheckPattern: "200 OK",
		},
		{
			Name:            "staging-basic",
			Type:            domain.DastAuthBasic,
			UsernameEnv:     "STAGING_BASIC_USER",
			PasswordEnv:     "STAGING_BASIC_PASS",
			SessionCheckURL: "https://app.example.test/account",
		},
		{
			Name:            "staging-browser",
			Type:            domain.DastAuthBrowser,
			LoginPageURL:    "https://app.example.test/login",
			LoginPageWait:   5,
			BrowserID:       "firefox-headless",
			UsernameEnv:     "STAGING_WEB_USER",
			PasswordEnv:     "STAGING_WEB_PASS",
			SessionCheckURL: "https://app.example.test/account",
		},
		{
			Name:             "staging-form",
			Type:             domain.DastAuthForm,
			LoginPageURL:     "https://app.example.test/login",
			LoginRequestURL:  "https://app.example.test/sessions",
			LoginRequestBody: "username={%username%}&password={%password%}",
			UsernameEnv:      "STAGING_WEB_USER",
			PasswordEnv:      "STAGING_WEB_PASS",
			LoggedInRegex:    "dashboard",
			LoggedOutRegex:   "sign in",
		},
	})
	if len(args) == 0 {
		return templates, nil
	}

	want := domain.NormalizeDastAuthType(args[0])
	for _, profile := range templates {
		if profile.Type == want {
			return []domain.DastAuthProfile{profile}, nil
		}
	}

	return nil, fmt.Errorf("unknown dast auth template type %q (expected bearer, header, basic, browser, or form)", args[0])
}
