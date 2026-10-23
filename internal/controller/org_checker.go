package controller

import (
	"context"

	ghclient "github.com/octovault/octovault/internal/github"
)

type OrgAccessChecker interface {
	CheckAccess(ctx context.Context, org, pwd string) (ghclient.AccessResult, error)
}
