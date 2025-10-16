package controller

import "context"

type OrgAccessChecker interface {
	Check(ctx context.Context, org, pwd string) error
}
