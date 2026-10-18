package controller

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

// 대상(ConfigMap/Secret) 소유는 ownerReference 가 아니라 어노테이션과 라벨로 표시한다.
//
// ownerReference 를 붙이면 쿠버네티스 GC 가 OctoVault 삭제 때 대상을 함께 지울 수 있다.
// 파이널라이저가 먼저 ownerReference 를 떼면 되지만, foreground 삭제(kubectl --cascade=foreground,
// Argo CD 앱 삭제)에서는 GC 가 dependent 를 바로 지우기 시작해 파이널라이저와 경쟁하게 되고,
// blockOwnerDeletion 으로도 막을 수 없다. "OctoVault 를 지워도 대상은 남는다"를 모든 삭제 방식에서
// 지키기 위해 GC 가 볼 수 있는 소유 관계를 아예 만들지 않는다.
//
//   - octovault.it/owner-uid: 관리하는 OctoVault 의 UID. 소유 판단의 기준이다.
//   - octovault.it/owner-ns, octovault.it/owner-name(라벨), octovault.it/owner(어노테이션):
//     어느 OctoVault 인지 이름으로 찾는 데 쓴다(watch 이벤트 연결, 삭제 시 대상 찾기, 재설치 시 이어받기).
//
// 이전 버전이 붙인 ownerReference(controller=이 OctoVault)도 소유로 인정하고, 다음 갱신 때 뗀다.

// ownedBy obj 가 이 OctoVault 의 대상인지 본다.
func ownedBy(obj metav1.Object, ov *octovaultv1alpha1.OctoVault) bool {
	if uid := obj.GetAnnotations()[AnnoOVOwnerUID]; uid != "" {

		return uid == string(ov.UID)
	}

	// 이전 버전이 만든 대상.
	return metav1.IsControlledBy(obj, ov)
}

// claimTarget 기존 대상을 이 OctoVault 가 관리해도 되는지 판단한다.
//
// 이미 소유한 대상이면 그대로 쓴다. 그렇지 않으면, ownerReference 로 다른 주체가 관리하지 않고
// octovault.it/adopt: "true" 가 붙은 대상만 이어받는다(adopted=true, 호출자가 owner-uid 를 새로 써
// 넣는다). 삭제 후 재설치(Helm/Argo)처럼 남겨진 대상을 다시 관리하려면 이 어노테이션을 한 번 붙이면
// 된다. 이어받으면서 대상의 어노테이션은 values.yaml 기준으로 다시 쓰이므로 adopt 는 한 번만 쓰인다.
//
// retained-from, owner 어노테이션, 옛 owner-uid 같은 흔적만으로는 이어받지 않는다. 그 흔적은 컨트롤러가
// 직접 남기므로, 그것만 믿으면 OctoVault 생성 권한만 있는 사용자가 지워진 OctoVault 와 같은 이름으로
// 만들어, 수정 권한이 없는 Secret 을 덮어쓸 수 있다. adopt 는 그 대상을 수정할 수 있는 주체만 붙일 수
// 있고, values.yaml 로는 넣을 수 없다(isReservedKey).
func claimTarget(obj *metav1.ObjectMeta, ov *octovaultv1alpha1.OctoVault) (adopted, owned bool) {
	if ownedBy(obj, ov) {

		return false, true
	}

	if metav1.GetControllerOf(obj) != nil || obj.GetAnnotations()[AnnoOVAdopt] != "true" {

		return false, false
	}

	return true, true
}

// dropLegacyOwnerRef 이전 버전이 붙인, uid 를 가리키는 ownerReference 를 뗀다. 뗐으면 true.
func dropLegacyOwnerRef(obj metav1.Object, uid types.UID) bool {

	owners := obj.GetOwnerReferences()
	kept := make([]metav1.OwnerReference, 0, len(owners))
	for _, o := range owners {
		if o.UID != uid {

			kept = append(kept, o)
		}
	}

	if len(kept) == len(owners) {

		return false
	}

	obj.SetOwnerReferences(kept)

	return true
}

// releaseTarget 이 OctoVault 의 소유 표시(owner-uid, 이전 버전의 ownerReference)를 지우고
// retained-from 을 남긴다. 지울 것이 있었으면 true.
func releaseTarget(obj metav1.Object, ov *octovaultv1alpha1.OctoVault) bool {

	changed := dropLegacyOwnerRef(obj, ov.UID)

	ann := obj.GetAnnotations()
	if ann[AnnoOVOwnerUID] == string(ov.UID) {

		delete(ann, AnnoOVOwnerUID)
		changed = true
	}

	if !changed {

		return false
	}

	if ann == nil {

		ann = map[string]string{}
	}

	ann[AnnoOVRetainedBy] = ov.Namespace + "/" + ov.Name
	obj.SetAnnotations(ann)

	return true
}

// mapTargetToOctoVault 대상의 변경을 그것을 관리하는 OctoVault 의 reconcile 요청으로 바꾼다.
//
// owner-name 라벨은 63자를 넘는 이름을 해시로 줄여 담으므로 이름을 그대로 되돌릴 수 없다.
// 같은 네임스페이스의 OctoVault 를 캐시에서 찾아 labelSafe(name) 으로 맞춘다. 라벨이 사라진 경우를
// 위해 owner 어노테이션("<ns>/<labelSafe(name)>")도 본다. owner-uid 가 있으면 UID 까지 맞춘다.
func (r *OctoVaultReconciler) mapTargetToOctoVault(ctx context.Context, obj client.Object) []reconcile.Request {

	ns, nameKey := obj.GetLabels()[LabelOVOwnerNS], obj.GetLabels()[LabelOVOwnerName]
	if ns == "" || nameKey == "" {

		ns, nameKey = splitOwner(obj.GetAnnotations()[AnnoOVOwnerFull])
	}

	if ns == "" || nameKey == "" {

		return nil
	}

	var list octovaultv1alpha1.OctoVaultList
	if err := r.List(ctx, &list, client.InNamespace(ns)); err != nil {

		return nil
	}

	uid := obj.GetAnnotations()[AnnoOVOwnerUID]
	reqs := make([]reconcile.Request, 0, 1)
	for i := range list.Items {

		ov := &list.Items[i]
		if labelSafe(ov.Name) != nameKey || (uid != "" && uid != string(ov.UID)) {

			continue
		}

		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ov.Namespace, Name: ov.Name}})
	}

	return reqs
}

// splitOwner "<ns>/<name>" 을 나눈다. 형식이 맞지 않으면 빈 문자열.
func splitOwner(v string) (string, string) {
	for i := 0; i < len(v); i++ {
		if v[i] == '/' {

			return v[:i], v[i+1:]
		}
	}

	return "", ""
}
