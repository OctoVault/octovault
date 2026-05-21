# Analysis 2 - METADATA - K8s Labels and Annotations Passthrough

## 기능 요구사항

- `octovault-values.yaml`의 `metadata` 섹션에 `annotations`와 `labels` 필드를 추가할 수 있다.
- OctoVault Controller가 생성하는 **Secret** 및 **ConfigMap** 오브젝트에 해당 annotations와 labels가 병합되어 적용된다.
- 사용자 정의 labels/annotations는 OctoVault 시스템 labels/annotations를 덮어쓰지 않는다.
  - 시스템 예약 키(`app.kubernetes.io/managed-by`, `octovault.it/*`, `reconcile.octovault.it/*`)는 사용자 값으로 덮어쓰기가 금지된다.
- values.yaml이 변경되면 다음 Reconcile 시 기존 리소스의 labels/annotations도 갱신된다.
- `annotations`와 `labels`는 각각 선택 사항이다 (없으면 빈 map으로 처리).

### 설정 예시

```yaml
metadata:
  type: Secret
  annotations:
    foo: bar
    team: backend
  labels:
    john: doe
    env: production
```

---

## 도메인 모델

### Entities

#### `valuesDoc` (내부 파싱 구조체, octovault_controller.go)

현재:
```go
type valuesDoc struct {
    Metadata struct {
        Type string `yaml:"type"`
    } `yaml:"metadata"`
    ...
}
```

변경 후:
```go
type valuesDoc struct {
    Metadata struct {
        Type        string            `yaml:"type"`
        Annotations map[string]string `yaml:"annotations,omitempty"`
        Labels      map[string]string `yaml:"labels,omitempty"`
    } `yaml:"metadata"`
    ...
}
```

#### `OctoVault` CR (api/v1alpha1/octovault_types.go)

- CRD Spec 변경 없음. 사용자 정의 metadata는 values.yaml에서만 관리한다.

### Value Objects

#### `UserMetadata`

사용자가 지정한 labels/annotations를 표현하는 value object.

```go
type UserMetadata struct {
    Annotations map[string]string
    Labels      map[string]string
}
```

- 예약 키 필터링 로직을 캡슐화한다.
- `FilterReservedKeys(reserved []string) UserMetadata` 메서드로 시스템 키 제거.

---

## Input / Output

### Input

| Source | Field | Type | Description |
|--------|-------|------|-------------|
| values.yaml | `metadata.annotations` | `map[string]string` | 사용자 정의 annotation map |
| values.yaml | `metadata.labels` | `map[string]string` | 사용자 정의 label map |

### Output

생성/업데이트되는 K8s 리소스의 `ObjectMeta`:

```
ObjectMeta.Labels      = merge(systemLabels, userLabels)      // system 우선
ObjectMeta.Annotations = merge(systemAnnotations, userAnnotations) // system 우선
```

- 병합 순서: 사용자 값 먼저 적용 후 시스템 값으로 덮어쓰기

---

## Related Functional Requirements

- **Analysis 1 (리팩토링)**: `applyConfigMap()` / `applySecret()` 함수 내 labels 적용 로직과 직접 연관. 리팩토링 결과에 따라 구현 위치가 달라질 수 있음.
- **해시 변경 감지**: `AppliedDataHash`는 `spec.data` 기반이므로 labels/annotations 변경만으로는 해시가 변경되지 않음. labels/annotations 변경도 갱신 트리거가 되어야 하는지 별도 확인 필요.
  - **가정**: 현재는 data 변경 시에만 리소스가 갱신됨. labels/annotations는 Reconcile이 트리거되면 항상 덮어쓰도록 구현 (매 Reconcile마다 apply).

---

## Solutions

### Solution A (채택): 병합 함수 + valuesDoc 확장

1. `valuesDoc.Metadata`에 `Annotations`, `Labels` 필드 추가
2. `mergeLabels(system, user map[string]string) map[string]string` 헬퍼 함수 추가
   - user map을 기본값으로, system map의 키가 항상 우선
   - 예약 prefix(`octovault.it/`, `reconcile.octovault.it/`, `app.kubernetes.io/`) 키는 user에서 제거
3. `applyConfigMap()`, `applySecret()` 내 ObjectMeta 설정 시 `mergeLabels` / `mergeAnnotations` 호출

**장점**:
- 최소 변경
- 기존 시스템 labels/annotations 보호 명확
- 테스트하기 쉬운 순수 함수

### Solution B: OctoVault CRD Spec에 UserMetadata 필드 추가

- CRD `.spec.metadata.labels`, `.spec.metadata.annotations` 필드 추가
- values.yaml 대신 CR에서 직접 지정

**단점**:
- values.yaml-driven 워크플로우와 불일치
- CRD 변경으로 호환성 영향
- 채택하지 않음

---

## Alternative Solutions

- **Annotation prefix 허용 목록**: 특정 prefix의 annotation만 허용 (보안 강화). 현재 요구사항에는 없으므로 미적용.
- **labels/annotations 변경 전용 해시**: `AppliedDataHash`를 data + labels + annotations 기반으로 변경. 별도 분석 필요, 현재 범위 외.

---

## Exceptions

| 케이스 | 처리 방법 |
|--------|-----------|
| 사용자가 `octovault.it/*` prefix 키 지정 | 해당 키 무시 (시스템 키 우선 병합으로 덮어쓰기) |
| 사용자가 `app.kubernetes.io/managed-by` 지정 | 무시 (시스템 키 우선) |
| `annotations` 또는 `labels` 필드 누락 | 빈 map으로 처리, 정상 동작 |
| values.yaml에서 labels/annotations 제거 후 Reconcile | 이전에 추가된 사용자 labels/annotations가 제거되어야 함 |
| label 값이 K8s label 규격 위반 (`>63자`, 특수문자) | values.yaml 파싱 후 K8s API 적용 시 오류 발생, Reconcile Failed 상태로 전환 |
| annotation 키/값에 빈 문자열 | 허용 (K8s 기본 동작 따름) |

---

## 비기능 요구사항

- labels/annotations 병합 로직은 순수 함수로 구현하여 단위 테스트 가능해야 한다.
- 기존 Reconcile 성능에 영향 없어야 한다 (O(n) 병합, n은 key 수).
- 예약 키 목록은 상수로 정의하여 유지보수 가능하게 한다.

---

## Constraints

- K8s label 값은 최대 63자, DNS subdomain 규칙 준수 필요.
- Annotation 키는 최대 253자 prefix + `/` + 63자 name.
- 시스템 예약 키는 반드시 보호되어야 함:
  - `app.kubernetes.io/managed-by`
  - `octovault.it/owner-ns`
  - `octovault.it/owner-name`
  - `octovault.it/owner`
  - `octovault.it/retained-from`
  - `reconcile.octovault.it/managed-by`
  - `reconcile.octovault.it/owner`
  - `reconcile.octovault.it/revision`
  - `reconcile.octovault.it/data-hash`

---

## External Infrastructure Services

없음. 이 기능은 순수하게 Controller 내부 로직 변경이며 외부 서비스와 무관하다.

---

## Red Task List

### 1. `valuesDoc` 파싱 - Annotations/Labels 필드 인식

- [ ] `metadata.annotations`가 있는 values.yaml 파싱 시 `valuesDoc.Metadata.Annotations`에 map이 채워짐
- [ ] `metadata.labels`가 있는 values.yaml 파싱 시 `valuesDoc.Metadata.Labels`에 map이 채워짐
- [ ] `metadata.annotations` / `metadata.labels` 필드가 없어도 파싱 오류 없이 빈 map으로 처리됨

### 2. `mergeLabels` / `mergeAnnotations` 순수 함수

- [ ] user map에 있는 키가 merged map에 포함됨
- [ ] system map에 있는 키가 user map의 동일 키를 덮어씀 (system 우선)
- [ ] user map이 nil이어도 system map만 반환되어 panic 없음
- [ ] system map이 nil이어도 user map만 반환됨
- [ ] 예약 prefix(`octovault.it/`, `reconcile.octovault.it/`, `app.kubernetes.io/`) 키는 user map에서 제거됨

### 3. ConfigMap 생성 - 사용자 labels/annotations 반영

- [ ] values.yaml에 `metadata.labels`가 있을 때 생성된 ConfigMap의 `ObjectMeta.Labels`에 포함됨
- [ ] values.yaml에 `metadata.annotations`가 있을 때 생성된 ConfigMap의 `ObjectMeta.Annotations`에 포함됨
- [ ] 시스템 labels(`app.kubernetes.io/managed-by`, `octovault.it/*`)는 사용자 값과 무관하게 항상 존재함
- [ ] 사용자가 시스템 키와 동일한 키를 지정해도 시스템 값이 유지됨

### 4. Secret 생성 - 사용자 labels/annotations 반영

- [ ] values.yaml에 `metadata.labels`가 있을 때 생성된 Secret의 `ObjectMeta.Labels`에 포함됨
- [ ] values.yaml에 `metadata.annotations`가 있을 때 생성된 Secret의 `ObjectMeta.Annotations`에 포함됨
- [ ] 시스템 labels/annotations는 항상 보존됨
- [ ] 사용자가 시스템 키 덮어쓰기 시도해도 시스템 값 유지됨

### 5. 업데이트 - labels/annotations 갱신

- [ ] values.yaml의 `metadata.labels`가 변경된 후 Reconcile 시 기존 ConfigMap/Secret의 labels가 갱신됨
- [ ] values.yaml에서 `metadata.labels` 전체 제거 후 Reconcile 시 이전 사용자 labels가 제거됨 (시스템 labels 유지)
- [ ] values.yaml에서 `metadata.annotations` 전체 제거 후 Reconcile 시 이전 사용자 annotations가 제거됨 (시스템 annotations 유지)
