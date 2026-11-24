package auth

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"testing"
)

func TestMergeUserInfo(t *testing.T) {
	for _, tc := range []struct {
		name, subject, profileSubject, email string
		wantErr                              bool
	}{
		{"same identity", "subject-a", "subject-a", " madhav@tulasatech.com ", false},
		{"different identity", "subject-a", "subject-b", "madhav@tulasatech.com", true},
		{"missing subject", "", "", "madhav@tulasatech.com", true},
		{"missing email", "subject-a", "subject-a", " ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := OIDCclaim{Sub: tc.subject}
			err := mergeUserInfo(&claims, &oidc.UserInfo{Subject: tc.profileSubject, Email: tc.email, EmailVerified: true})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			if !tc.wantErr && (claims.Email != "madhav@tulasatech.com" || !claims.EmailVerified) {
				t.Fatal("profile not merged")
			}
			if tc.wantErr && claims.Email != "" {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}
