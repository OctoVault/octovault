package main

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RBAC(이 CRD 하나에 대한 get)는 internal/controller/octorepository_controller.go 의 마커에 있다.

// errStaleCRD 설치된 CRD 가 이 컨트롤러가 기대하는 필드를 모른다.
var errStaleCRD = errors.New("installed CRDs are older than this controller")

const octoRepositoryCRD = "octorepositories.octovault.it"

var (
	crdGVK = schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"}

	// allowedNamespacesSchemaPath CRD 버전 안에서 spec.allowedNamespaces 스키마의 위치.
	allowedNamespacesSchemaPath = []string{
		"schema", "openAPIV3Schema", "properties", "spec", "properties", "allowedNamespaces",
	}
)

// verifyCRDs 설치된 OctoRepository CRD 가 spec.allowedNamespaces 를 아는지 확인한다.
//
// helm upgrade 는 차트의 crds/ 를 갱신하지 않는다. 옛 CRD 에서는 API 서버가 모르는 필드를 지워 버리므로
// allowedNamespaces 가 조용히 사라지고, 빈 목록은 "모든 네임스페이스 허용"이라 제한이 풀린 채 동작한다.
// 그래서 필드가 없는 것을 확인하면 errStaleCRD 를 돌려 시작을 막는다(fail-closed).
// CRD 를 읽지 못하면(권한 등) 판단할 수 없으므로 그 오류를 그대로 돌려준다. 호출자는 이때도 시작하지 않는다.
func verifyCRDs(ctx context.Context, c client.Reader) error {

	crd := &unstructured.Unstructured{}
	crd.SetGroupVersionKind(crdGVK)
	if err := c.Get(ctx, client.ObjectKey{Name: octoRepositoryCRD}, crd); err != nil {

		return fmt.Errorf("read CRD %s: %w", octoRepositoryCRD, err)
	}

	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for _, v := range versions {

		m, ok := v.(map[string]interface{})
		if !ok || m["name"] != "v1alpha1" {

			continue
		}

		if _, found, _ := unstructured.NestedMap(m, allowedNamespacesSchemaPath...); found {

			return nil
		}
	}

	return fmt.Errorf("%w: %s has no spec.allowedNamespaces, so the API server would silently drop it and "+
		"every namespace would be allowed; apply the CRDs before starting this version "+
		"(kubectl apply -f charts/octovault/crds/)", errStaleCRD, octoRepositoryCRD)
}
