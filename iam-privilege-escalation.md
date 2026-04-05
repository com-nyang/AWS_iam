# IAM Privilege Escalation

## One-Line Definition

IAM Privilege Escalation은 낮은 권한을 가진 주체가 IAM의 허점을 이용해 더 높은 권한을 획득하는 공격 패턴이다.

## Why It Matters

IAM 공부에서 Privilege Escalation을 봐야 하는 이유는 하나다.

권한 설계의 약점이 어디서 생기는지 이해하지 못하면, 올바른 권한 설계를 할 수 없다.

"최소 권한 원칙(Least Privilege)"이라는 말은 자주 나오지만, 실제로 어떤 권한이 왜 위험한지 모르면 적용할 수 없다. Privilege Escalation 패턴을 배우면 각 IAM 액션이 왜 민감한지, 어떤 조합이 왜 위험한지 구체적으로 보인다.

## 핵심 전제: IAM의 권한 평가 구조

Privilege Escalation을 이해하려면 IAM 권한 평가의 기본 전제를 먼저 알아야 한다.

**기본값은 거부다.** 명시적으로 허용된 것만 할 수 있다.

**명시적 Deny는 항상 이긴다.** Allow가 있어도 Deny가 있으면 막힌다.

**권한 평가는 요청 시점에 일어난다.** 정책을 저장할 때가 아니라, 실제 API 호출이 일어날 때 평가된다.

이 구조에서 Privilege Escalation이 가능한 이유는 이렇다.

> 낮은 권한의 주체가 자기 자신이나 다른 주체의 권한을 바꿀 수 있는 IAM 액션을 가지고 있을 때

즉 "내가 직접 강한 권한을 받은 게 아니라, 내가 강한 권한을 스스로 만들어낼 수 있는 상황"이 문제다.

## 패턴 분류

IAM Privilege Escalation 패턴은 크게 세 가지로 나뉜다.

1. **직접 권한 확장** — 자기 자신에게 직접 권한을 추가하거나 수정
2. **Role 탈취** — AssumeRole을 이용해 더 강한 Role로 이동
3. **서비스 우회** — 다른 AWS 서비스를 경유해서 권한을 우회적으로 획득

---

## 패턴 1. 직접 권한 확장

### 1-1. iam:CreatePolicyVersion

기존 정책에 새 버전을 만들 수 있는 권한이다.

IAM 정책은 버전을 여러 개 가질 수 있다. 그리고 어떤 버전을 "기본값"으로 쓸지 지정할 수 있다.

```
기존 정책: version 1 (읽기만 허용)
          version 2 (새로 만든 버전, Action: *, Resource: *)  ← 이걸 기본으로 설정
```

이 권한 하나만 있어도 기존 정책에 관리자급 버전을 추가하고, 그걸 기본으로 바꿀 수 있다.

관련 액션:

- `iam:CreatePolicyVersion`
- `iam:SetDefaultPolicyVersion`

### 1-2. iam:AttachUserPolicy / iam:AttachRolePolicy / iam:AttachGroupPolicy

자기 자신이나 다른 주체에게 관리형 정책을 직접 붙일 수 있는 권한이다.

예를 들어 `iam:AttachUserPolicy`가 있으면 아래처럼 자기 자신에게 `AdministratorAccess`를 붙일 수 있다.

```bash
aws iam attach-user-policy \
  --user-name my-own-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 1-3. iam:PutUserPolicy / iam:PutRolePolicy

인라인 정책을 직접 작성해서 붙이는 권한이다.

관리형 정책이 아니라 인라인 정책을 새로 써서 붙이는 방식이다. 제한이 더 느슨한 경우가 많다.

```bash
aws iam put-user-policy \
  --user-name my-own-user \
  --policy-name escalation \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### 1-4. iam:AddUserToGroup

특정 그룹에 자기 자신을 추가할 수 있는 권한이다.

그 그룹에 강한 권한이 붙어 있다면, 그룹에 들어가는 것만으로 그 권한을 전부 얻는다.

```bash
aws iam add-user-to-group \
  --group-name AdminGroup \
  --user-name my-own-user
```

### 1-5. iam:UpdateLoginProfile / iam:CreateLoginProfile

다른 IAM User의 콘솔 비밀번호를 바꾸거나 새로 만들 수 있는 권한이다.

직접 권한을 올리는 게 아니라, 관리자 User의 비밀번호를 바꿔서 그 계정으로 로그인하는 방식이다.

### 1-6. iam:CreateAccessKey

다른 IAM User의 Access Key를 새로 발급할 수 있는 권한이다.

관리자 User에게 새 Access Key를 발급하면, 그 키로 관리자 권한을 사용할 수 있다.

---

## 패턴 2. Role 탈취 / 조작

### 2-1. iam:UpdateAssumeRolePolicy

특정 Role의 Trust Policy를 수정할 수 있는 권한이다.

Trust Policy는 "누가 이 Role을 assume할 수 있는가"를 정의한다. 이걸 바꿀 수 있으면 자기 자신을 신뢰하는 Principal로 추가할 수 있다.

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:user/low-priv-user"
  },
  "Action": "sts:AssumeRole"
}
```

이렇게 바꿔두면 `sts:AssumeRole`만 호출하면 더 강한 Role을 맡을 수 있다.

### 2-2. sts:AssumeRole 체이닝

직접 관리자 Role을 assume하지 않아도, 중간 Role을 여러 개 거치면서 권한을 점점 높이는 방식이다.

```
low-priv-user
  → AssumeRole → RoleA (약한 권한이지만 RoleB assume 가능)
    → AssumeRole → RoleB (강한 권한)
```

개별 Role 하나만 봐서는 위험해 보이지 않아도, 연결했을 때 경로가 생긴다.

---

## 패턴 3. 서비스 우회 (iam:PassRole)

가장 중요하고, 가장 자주 발생하는 패턴이다.

### iam:PassRole이란

어떤 주체가 특정 Service에게 IAM Role을 "넘길 수 있는" 권한이다.

예를 들어 EC2 인스턴스를 생성할 때 Instance Profile(Role)을 붙이려면 `iam:PassRole`이 필요하다. Lambda 함수를 만들 때 Execution Role을 지정하는 것도 마찬가지다.

### 왜 위험한가

`iam:PassRole`이 있으면 직접 assume하지 않아도 된다. 서비스가 대신 그 Role로 동작하게 만들 수 있다.

```
나: EC2 RunInstances 권한 + iam:PassRole 권한
관리자 Role: 강한 권한 보유
흐름: 내가 EC2를 생성하면서 관리자 Role을 붙임
      → EC2 안에서 그 Role의 임시 자격증명을 가져다 씀
      → 관리자 권한으로 API 호출
```

내가 직접 관리자 Role을 assume하지 않았지만, EC2를 경유해서 결국 관리자 권한을 사용하게 된다.

### 3-1. EC2 + iam:PassRole

```
필요한 권한: ec2:RunInstances + iam:PassRole
흐름:
  1. 관리자 Role이 붙은 EC2 인스턴스를 생성
  2. 인스턴스에 SSH 접속
  3. 인스턴스 메타데이터에서 임시 자격증명 획득
  4. 관리자 권한으로 API 호출
```

인스턴스 메타데이터 엔드포인트:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName
```

### 3-2. Lambda + iam:PassRole

```
필요한 권한: lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole
흐름:
  1. 관리자 Role을 Execution Role로 지정해서 Lambda 함수 생성
  2. 함수 안에 원하는 코드 작성 (예: 새 관리자 User 생성)
  3. 함수 호출
  4. 함수가 관리자 권한으로 실행됨
```

### 3-3. CloudFormation + iam:PassRole

```
필요한 권한: cloudformation:CreateStack + iam:PassRole
흐름:
  1. 관리자 Role을 Service Role로 지정한 CloudFormation 스택 생성
  2. 스택 템플릿 안에 원하는 리소스 정의 (예: 관리자 User)
  3. CloudFormation이 그 Role의 권한으로 템플릿 실행
```

### 3-4. Glue + iam:PassRole

```
필요한 권한: glue:CreateDevEndpoint + iam:PassRole
흐름:
  1. 관리자 Role을 붙인 Glue Development Endpoint 생성
  2. Endpoint에 접속해서 임시 자격증명 사용
```

---

## 전체 패턴 요약

| 패턴 | 핵심 액션 | 방식 |
|------|-----------|------|
| 정책 버전 추가 | `iam:CreatePolicyVersion` | 기존 정책에 관리자급 버전 추가 |
| 정책 직접 부착 | `iam:AttachUserPolicy` 등 | 자기 자신에게 강한 정책 붙이기 |
| 인라인 정책 작성 | `iam:PutUserPolicy` 등 | 직접 작성한 정책 붙이기 |
| 그룹 합류 | `iam:AddUserToGroup` | 강한 권한 그룹에 자기 추가 |
| 비밀번호 변경 | `iam:UpdateLoginProfile` | 관리자 계정 비밀번호 탈취 |
| Access Key 발급 | `iam:CreateAccessKey` | 관리자 계정 키 발급 |
| Trust Policy 수정 | `iam:UpdateAssumeRolePolicy` | 강한 Role의 신뢰 대상에 자기 추가 |
| Role 체이닝 | `sts:AssumeRole` 반복 | 중간 Role 거쳐 권한 상승 |
| EC2 우회 | `ec2:RunInstances` + `iam:PassRole` | EC2에 강한 Role 붙여서 접근 |
| Lambda 우회 | `lambda:CreateFunction` + `iam:PassRole` | Lambda에 강한 Role 붙여서 실행 |
| CloudFormation 우회 | `cloudformation:CreateStack` + `iam:PassRole` | 스택으로 원하는 리소스 생성 |

---

## iam:PassRole 제한 방법

`iam:PassRole`은 완전히 막을 수 없다. 서비스 간 연동에 필요하기 때문이다. 하지만 범위를 좁힐 수 있다.

`Resource`로 어떤 Role만 넘길 수 있는지 제한한다.

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/OnlyThisRole"
}
```

이렇게 하면 `OnlyThisRole`만 서비스에 넘길 수 있다. `*`로 열어두면 계정 안의 모든 Role을 넘길 수 있어서 위험하다.

## Common Misunderstandings

- "읽기 권한만 있으면 안전하다"
  아니다. `iam:CreatePolicyVersion`이나 `iam:PassRole`처럼 얼핏 무해해 보이는 권한도 조합에 따라 상승 경로가 생긴다.

- "자기 자신의 권한을 바꾸는 건 당연히 막혀 있다"
  아니다. IAM은 기본적으로 자기 자신도 Policy의 대상이 될 수 있다. 명시적으로 막지 않으면 자기 자신에게 정책을 붙일 수 있다.

- "iam:PassRole은 assume이 아니니까 괜찮다"
  아니다. 서비스를 경유한 우회 경로가 생긴다. EC2나 Lambda를 통해 결국 그 Role의 권한을 사용하게 된다.

- "관리형 정책만 통제하면 된다"
  아니다. 인라인 정책(`iam:PutUserPolicy`)도 같은 효과를 낸다. 관리형과 인라인 모두 통제해야 한다.

## Operational Takeaways

- IAM 정책을 설계할 때 `iam:*`, `sts:*` 계열 액션은 전체 허용하지 않는다.
- `iam:PassRole`은 반드시 `Resource`로 특정 Role ARN만 지정한다.
- 어떤 주체가 가진 권한 목록만 보지 말고, 그 권한으로 어떤 IAM 조작이 가능한지 같이 본다.
- 권한 설계 후에는 "이 주체가 자기 권한을 스스로 올릴 수 있는가"를 확인한다.
- 특히 개발자 계정에 `iam:PassRole`과 `lambda:*` 또는 `ec2:*`가 함께 있는 구조는 주의한다.

## Detection / Logging Angle

Privilege Escalation 시도는 CloudTrail에 모두 기록된다. 아래 이벤트가 비정상적으로 발생하면 확인이 필요하다.

| CloudTrail 이벤트 | 의미 |
|------------------|------|
| `CreatePolicyVersion` | 정책에 새 버전 추가 |
| `SetDefaultPolicyVersion` | 기본 정책 버전 변경 |
| `AttachUserPolicy` / `AttachRolePolicy` | 정책 부착 |
| `PutUserPolicy` / `PutRolePolicy` | 인라인 정책 작성 |
| `AddUserToGroup` | 그룹 추가 |
| `UpdateAssumeRolePolicy` | Trust Policy 수정 |
| `CreateAccessKey` | Access Key 발급 |
| `UpdateLoginProfile` | 비밀번호 변경 |
| `AssumeRole` | Role 전환 (반복적으로 발생 시 체이닝 의심) |

특히 자기 자신을 대상으로 한 `AttachUserPolicy`, `PutUserPolicy`는 즉시 확인이 필요하다.

## Suggested Next Step

1. `iam:PassRole`과 서비스 Role 설계 심화
2. IAM Permission Boundary — Privilege Escalation을 제도적으로 막는 방법
3. AWS SCPs (Service Control Policies) — 조직 수준에서 IAM 액션 제한
4. Cross-account trust 설계 패턴
