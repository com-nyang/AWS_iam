# IAM Basics

## One-Line Definition

IAM(Identity and Access Management)은 "누가, 어떤 리소스에, 어떤 조건으로, 무엇을 할 수 있는가"를 통제하는 체계다.

## Why IAM Comes First

클라우드 보안에서 가장 먼저 봐야 할 것은 네트워크보다도 권한이다. 공격자는 시스템 취약점만 노리는 것이 아니라, 과도한 권한, 노출된 access key, 잘못 열린 trust policy, 약한 인증 체계를 이용해 가장 빠르게 확장한다.

즉 IAM은 단순한 계정 관리 기능이 아니라, 클라우드 전체 보안의 출입문이자 확장 경로다.

## The Big Picture

IAM을 깊게 이해하려면 아래 5개 질문으로 계속 정리해야 한다.

1. 누가 요청을 보내는가
2. 그 요청은 어떤 자격증명을 사용하는가
3. 어떤 정책이 그 요청에 적용되는가
4. 어떤 조건에서 허용 또는 거부되는가
5. 그 행위는 로그에 어떻게 남는가

이 5개가 연결되면 IAM 구조가 보인다.

## Core Building Blocks

### Identity

Identity는 "행위를 하는 주체"다. 사람, 애플리케이션, 서비스, 워크로드가 모두 주체가 될 수 있다.

클라우드에서 이 주체는 보통 아래 형태로 나타난다.

- User
- Group
- Role
- Federated Identity
- Service Principal 또는 Service Account류 개념

### Credential

Credential은 그 주체가 자신을 증명하는 수단이다.

예:

- 비밀번호
- MFA
- Access Key
- Temporary Credential
- SSO 토큰
- AssumeRole 세션

Identity와 Credential은 다르다.  
Identity는 "누구인가"이고, Credential은 "그 사실을 어떻게 증명하는가"다.

### Permission

Permission은 어떤 액션을 어떤 리소스에 대해 수행할 수 있는지에 대한 규칙이다.

실제 권한은 보통 Policy 안에 들어 있다.

### Policy

Policy는 허용 또는 거부 규칙 문서다. 어떤 주체가 어떤 액션을 어떤 리소스에 대해 할 수 있는지 기술한다.

### Trust

Trust는 "누가 이 역할을 맡을 수 있는가"를 정의한다.  
특히 Role을 이해할 때 핵심이다.

Permission policy가 "이 역할이 무엇을 할 수 있는가"라면, trust policy는 "누가 이 역할을 맡을 수 있는가"다.

## User, Group, Role Deep Dive

### User

User는 장기적으로 존재하는 개별 계정이다. 사람 또는 애플리케이션에 대응될 수 있다.

특징:

- 장기적으로 유지되는 정체성
- 콘솔 로그인 또는 access key를 가질 수 있음
- 관리가 느슨하면 장기 자격증명이 보안 부채가 됨

주의할 점:

- 사람에게 강한 권한을 직접 붙여두는 운영은 위험하다
- 장기 access key는 특히 관리가 어렵다
- 퇴사자/미사용 계정 정리가 안 되면 공격 표면이 된다

### Group

Group은 여러 User에 공통 권한을 묶어서 부여하기 위한 구조다.

특징:

- 로그인 주체는 아님
- 권한 관리 편의성을 높임
- 비슷한 직무의 사용자에게 동일 정책을 적용할 때 유용

핵심:

Group은 권한을 구조화하는 도구이지, 실행 주체가 아니다.

### Role

Role은 특정 권한 세트를 임시로 위임받기 위한 정체성이다.

특징:

- 보통 장기 비밀번호나 access key를 직접 들고 있지 않음
- 누군가가 assume 해서 사용
- 서비스, 사람, 다른 계정, 워크로드가 사용할 수 있음
- 임시 자격증명과 강하게 연결됨

왜 중요한가:

- 장기 자격증명보다 안전한 운영이 가능함
- 서비스 간 접근을 깔끔하게 설계할 수 있음
- 크로스어카운트 접근 통제의 핵심이 됨

### User vs Role

가장 많이 헷갈리는 부분이다.

- User
  장기적으로 존재하는 계정
- Role
  필요할 때만 맡는 권한 단위

실무에서는 사람에게 직접 관리자 권한을 계속 붙이기보다,

1. 기본 계정은 약하게 두고
2. 필요할 때 Role을 assume 하며
3. 작업이 끝나면 세션이 만료되게

운영하는 쪽이 더 안전하다.

## Policy Deep Dive

Policy는 IAM의 핵심이다. User, Group, Role은 권한을 담는 그릇이고, 실제 권한 내용은 Policy가 결정한다.

보통 정책은 아래 요소를 가진다.

- Effect
- Action
- Resource
- Condition
- Principal

### Effect

`Allow` 또는 `Deny`를 뜻한다.

중요한 원칙:

- 명시적 Allow가 있어야 허용된다
- 명시적 Deny는 Allow보다 우선한다

### Action

주체가 수행하려는 동작이다.

예:

- `s3:GetObject`
- `ec2:StartInstances`
- `iam:PassRole`

### Resource

권한이 적용되는 대상이다.

예:

- 특정 S3 버킷
- 특정 EC2 인스턴스
- 특정 KMS 키

### Condition

특정 조건에서만 권한이 동작하도록 제한하는 요소다.

예:

- 특정 IP에서만 허용
- MFA가 있을 때만 허용
- 특정 태그를 가진 리소스에만 허용
- 특정 시간대에만 허용

### Principal

누가 이 정책의 대상인지 나타낸다. 특히 Resource-based policy나 trust policy에서 중요하다.

## Policy JSON Examples

IAM을 글로만 보면 막연할 수 있다. 실제로는 보통 아래처럼 JSON 문서로 권한이 표현된다.

### Example 1. Identity-Based Policy

아래 예시는 특정 버킷에 대해 읽기 권한만 주는 가장 기본적인 형태다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOnlyToOneBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket",
        "arn:aws:s3:::example-bucket/*"
      ]
    }
  ]
}
```

이 JSON을 읽는 방법:

- `Effect`
  허용인지 거부인지
- `Action`
  무엇을 할 수 있는지
- `Resource`
  어디에 대해 할 수 있는지

즉 이 정책은 "example-bucket에 대해 목록 조회와 객체 읽기만 허용한다"는 뜻이다.

### Example 2. Policy With Condition

아래 예시는 MFA가 있을 때만 특정 IAM 작업을 허용하는 예시다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSensitiveActionOnlyWithMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey"
      ],
      "Resource": "arn:aws:iam::123456789012:user/luke",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

핵심은 `Condition`이다.  
권한을 단순히 주는 것이 아니라 "특정 조건을 만족할 때만" 권한이 작동하게 만든다.

### Example 3. Explicit Deny

아래 예시는 특정 리전에 대해 리소스 생성을 막는 예시다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideApprovedRegion",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": "ap-northeast-2"
        }
      }
    }
  ]
}
```

이 예시의 의미:

- `Action: "*"`
  모든 액션에 적용
- `Resource: "*"`
  모든 리소스에 적용
- `Effect: "Deny"`
  특정 조건이면 전부 막음

즉 명시적 Deny가 얼마나 강력한지 보여주는 예시다.

### Example 4. Trust Policy

아래 예시는 EC2 서비스가 특정 Role을 assume할 수 있게 하는 trust policy다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

이 JSON은 권한 자체를 주는 것이 아니라:

- 누가
- 어떤 방식으로
- 이 Role을 맡을 수 있는지

를 정의한다.

즉 이 문서는 "EC2가 이 Role을 맡을 수 있다"는 의미다.

### Example 5. Cross-Account Trust Policy

아래 예시는 다른 계정의 특정 Role만 내 계정의 Role을 assume할 수 있게 하는 예시다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/SecurityAuditRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

이런 식으로 trust policy는 크로스어카운트 접근의 입구를 만든다.  
따라서 `Principal`을 너무 넓게 열면 매우 위험해질 수 있다.

### Example 6. Resource-Based Policy

아래 예시는 특정 AWS 계정만 S3 버킷에 접근할 수 있게 하는 버킷 정책 예시다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadFromSpecificAccount",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
```

이 정책은 identity에 붙는 것이 아니라 리소스 자체에 붙는다.  
즉 "이 버킷 입장에서 누가 들어올 수 있는가"를 정하는 방식이다.

## How To Read IAM JSON

IAM JSON을 보면 항상 아래 순서로 읽는 습관을 들이면 좋다.

1. `Effect`를 본다
허용인지 거부인지 먼저 본다.

2. `Action`을 본다
무슨 행동을 허용하거나 막는지 본다.

3. `Resource`를 본다
대상이 특정 리소스인지 전체 리소스인지 본다.

4. `Principal`이 있는지 본다
trust policy나 resource policy라면 "누가 대상인가"를 본다.

5. `Condition`을 본다
IP, MFA, 태그, 시간, 리전 등 추가 제한이 있는지 본다.

6. 와일드카드가 있는지 본다
`*`가 많을수록 위험할 가능성이 높다.

## Red Flags In JSON Policies

JSON 정책을 볼 때 아래 패턴은 특히 주의해서 봐야 한다.

- `Action: "*"`
- `Resource: "*"`
- `Principal: "*"`
- `Effect: "Allow"`인데 조건이 전혀 없음
- trust policy에서 너무 넓은 Principal 허용
- 민감한 IAM 액션이 광범위하게 열려 있음

예를 들면 아래는 매우 위험한 예시다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

이건 사실상 관리자 권한과 비슷한 의미로 작동할 수 있다.

## Practical Questions And Answers

IAM을 공부하다 보면 아래 질문에서 많이 막힌다. 이 부분을 같이 이해해야 정책 문서를 실제로 읽을 수 있다.

### Q1. 기본값이 Deny인데, Effect를 Deny만 설정해서 특정 리전만 막는 식도 가능한가

가능하다. 다만 전제가 있다.

IAM의 기본값은 이미 거부다. 그래서 `Deny` 정책만 단독으로 달아두면 "특정 리전만 막고 나머지는 허용"이 되는 것이 아니라, 원래 기본적으로 다 막혀 있다.

이 말은 곧:

- 다른 곳에서 `Allow`가 이미 있고
- 그 위에 특정 조건의 `Deny`를 덧씌울 때

의미가 생긴다는 뜻이다.

예를 들어:

- 정책 A
  `ec2:RunInstances` 허용
- 정책 B
  서울 리전이 아니면 `ec2:RunInstances` 거부

이렇게 되면 서울에서는 가능하고, 다른 리전에서는 명시적 Deny 때문에 막힌다.

예시:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideSeoul",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": "ap-northeast-2"
        }
      }
    }
  ]
}
```

이 정책은 "서울이 아닌 리전에서는 인스턴스 생성을 막는다"는 뜻이다.  
하지만 서울에서 진짜 생성되려면 별도의 `Allow`가 필요하다.

### Q2. 한 번에 여러 개의 Effect를 넣을 수도 있는가

한 `Statement` 안에는 안 된다.

`Effect`는 statement마다 하나만 가질 수 있다.

가능한 값은 보통:

- `Allow`
- `Deny`

둘 중 하나다.

즉 아래 같은 형태는 안 된다.

```json
{
  "Effect": ["Allow", "Deny"]
}
```

대신 여러 규칙을 표현하려면 `Statement`를 여러 개 둔다.

예:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRead",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    },
    {
      "Sid": "DenyDelete",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
```

즉 Policy 안에는 여러 `Statement`가 들어갈 수 있지만, 각 `Statement`는 하나의 `Effect`만 가진다.

### Q3. AWS에서는 권한을 보통 어떻게 나누는가

AWS에는 정해진 정답 구조가 있는 것은 아니다. 다만 실무에서는 보통 `Role로 책임 단위를 나누고`, `Policy로 세부 권한을 붙이는 방식`으로 설계한다.

핵심은 이렇다.

- `Role`
  누가 어떤 상황에서 권한을 사용하는가
- `Policy`
  그 역할이 정확히 무엇을 할 수 있는가

즉 실무에서는 "권한 자체"보다 먼저 "역할 분리"를 설계한다.

### Q4. AWS에서는 어떤 Role들이 자주 나오는가

보통 아래처럼 나눈다.

#### 사람용 Role

사람이 콘솔 또는 CLI로 작업할 때 맡는 역할이다.

예:

- `AdminRole`
- `DeveloperRole`
- `ReadOnlyRole`
- `SecurityAuditRole`
- `NetworkAdminRole`

#### 서비스용 Role

AWS 서비스나 워크로드가 다른 리소스에 접근할 때 쓰는 역할이다.

예:

- `EC2AppRole`
- `LambdaExecutionRole`
- `ECSTaskRole`
- `CloudFormationExecutionRole`

#### 크로스어카운트 Role

다른 AWS 계정이 내 계정에 접근할 때 쓰는 역할이다.

예:

- `CrossAccountAuditRole`
- `DeploymentRole`

#### 긴급/승격 Role

평소에는 사용하지 않고 필요할 때만 맡는 역할이다.

예:

- `BreakGlassAdminRole`
- `EmergencyAccessRole`

### Q5. AWS에서는 어떤 Policy들이 자주 나오는가

보통 아래처럼 나눈다.

#### AWS Managed Policy

AWS가 미리 만들어 둔 정책이다.

예:

- `AdministratorAccess`
- `ReadOnlyAccess`
- `PowerUserAccess`
- `AmazonS3ReadOnlyAccess`

장점:

- 빠르게 적용 가능

단점:

- 너무 넓은 경우가 많음

#### Customer Managed Policy

조직이 직접 만드는 정책이다.

예:

- `AppS3ReadOnlyPolicy`
- `EC2StartStopPolicy`
- `SecurityAuditPolicy`
- `KMSDecryptForAppPolicy`

이게 실무에서 더 중요하다.  
업무에 맞춰 최소 권한으로 잘라낼 수 있기 때문이다.

#### Inline Policy

특정 User 또는 Role 하나에만 직접 붙는 정책이다.

재사용성과 관리성이 떨어져서 남발하지 않는 편이 좋다.

### Q6. AWS IAM은 실무에서 보통 어떤 구조로 운영하나

보통은 아래 순서로 설계한다.

1. 사람용 역할, 서비스용 역할, 감사용 역할, 배포용 역할을 먼저 나눈다
2. 각 역할이 해야 하는 액션을 정의한다
3. 그 액션만 담은 정책을 만든다
4. 필요하면 trust policy와 condition으로 더 제한한다

즉 구조는 보통 아래처럼 이해하면 된다.

`사람/서비스 -> Role Assume -> Policy 평가 -> Resource 접근`

### Q7. AWS에서 자주 보이는 좋은 패턴은 무엇인가

- 사람에게 직접 강한 권한을 붙이지 않고 Role 중심으로 운영
- 서비스마다 전용 Role 분리
- AWS Managed Policy로 시작하되 점점 Customer Managed Policy로 줄여감
- 임시 자격증명 중심 운영
- 크로스어카운트 접근은 별도 Role로 분리
- 관리자 권한은 상시 부여하지 않고 승격형 Role 사용

### Q8. AWS에서 자주 보이는 나쁜 패턴은 무엇인가

- 모든 사람에게 `AdministratorAccess`
- 여러 애플리케이션이 하나의 공용 Role 공유
- `Action: "*"`와 `Resource: "*"` 남발
- trust policy를 너무 넓게 오픈
- 코드 안에 access key 하드코딩
- 읽기 전용이라고 하면서 민감 데이터 조회 권한까지 광범위하게 허용

## Types Of Policies

클라우드마다 이름은 다르지만, 보통 아래 유형으로 나눠 생각하면 된다.

### Identity-Based Policy

User, Group, Role에 붙는 정책이다.

즉 "이 주체가 무엇을 할 수 있는가"를 정의한다.

### Resource-Based Policy

리소스 자체에 붙는 정책이다.

즉 "누가 이 리소스에 접근할 수 있는가"를 리소스 관점에서 정의한다.

예:

- S3 Bucket Policy
- KMS Key Policy

### Trust Policy

Role에 대해 "누가 이 역할을 assume할 수 있는가"를 정의하는 정책이다.

Permission policy와 trust policy를 혼동하면 안 된다.

- Permission policy
  역할이 맡겨진 뒤 무엇을 할 수 있는가
- Trust policy
  누가 그 역할을 맡을 수 있는가

### Boundary / Guardrail Policy

권한의 최대 범위를 제한하는 역할을 하는 정책들이다.

예:

- Permissions Boundary
- SCP(Service Control Policy)류 조직 차원의 정책

이들은 보통 "아무리 Allow가 있어도 여기서 막히면 못 한다"는 상한선 역할을 한다.

## IAM Evaluation Logic

IAM을 깊게 이해하려면 "권한 평가 순서"를 꼭 알아야 한다.

아래처럼 생각하면 된다.

1. 요청이 들어온다
2. 누가 요청했는지 식별한다
3. 그 주체에 적용되는 정책을 모은다
4. 관련 resource policy나 조직 정책, boundary를 함께 본다
5. 명시적 Deny가 있는지 본다
6. 명시적 Allow가 있는지 본다
7. 둘 다 없으면 기본적으로 거부된다

핵심 규칙은 3개다.

1. 기본값은 거부다
2. Allow가 있어야 허용된다
3. Deny는 Allow보다 강하다

## Authentication vs Authorization

많이 섞어 쓰지만 다른 개념이다.

### Authentication

"너는 누구냐"를 확인하는 단계다.

예:

- 비밀번호
- MFA
- SSO 로그인
- access key 서명 검증

### Authorization

"그렇다면 무엇을 할 수 있느냐"를 결정하는 단계다.

즉 IAM은 둘 다 포함하지만, 구조적으로는 인증과 인가를 분리해서 봐야 한다.

## Temporary Credential vs Long-Term Credential

IAM에서 가장 중요한 운영 철학 중 하나다.

### Long-Term Credential

장기적으로 유지되는 자격증명이다.

예:

- 비밀번호
- access key

문제점:

- 유출되면 오래 악용될 수 있음
- 회전이 잘 안 됨
- 누가 어디에 저장했는지 관리가 어려움

### Temporary Credential

짧은 수명을 가진 임시 자격증명이다.

예:

- AssumeRole 세션
- STS 기반 임시 키
- 워크로드 아이덴티티 기반 임시 토큰

장점:

- 수명이 짧음
- 자동 회전이 쉬움
- 장기 비밀 저장을 줄일 수 있음

결론적으로, 현대 IAM 운영은 장기 자격증명을 줄이고 임시 자격증명 중심으로 가는 방향이 맞다.

## Federation And SSO

실무에서는 User를 클라우드 계정 안에 무한정 직접 만들지 않는 방향으로 많이 간다.

그 대신:

- 기업 IdP
- SSO
- Federation

을 통해 기존 사용자 체계를 클라우드와 연결한다.

이 방식의 장점:

- 계정 수명주기 중앙 관리
- 입사/퇴사 반영 쉬움
- MFA 일관 적용 가능
- 감사 관점이 좋아짐

즉 IAM은 클라우드 안의 로컬 계정 관리만이 아니라, 외부 정체성 체계와 연결되는 구조까지 포함한다.

## Service-To-Service IAM

클라우드에서는 사람만 IAM을 쓰는 것이 아니다. 서비스와 워크로드가 훨씬 더 많이 쓴다.

예:

- EC2가 S3에 접근
- Lambda가 DynamoDB에 접근
- Kubernetes 워크로드가 KMS를 호출

이때 핵심 원칙:

- access key를 코드에 박지 말 것
- Role 또는 workload identity를 사용할 것
- 필요한 리소스에 최소 권한만 줄 것

## Least Privilege Deep Dive

Least Privilege는 "최소 권한"으로 번역되지만, 단순히 권한을 적게 주는 것이 아니다.

정확한 의미는:

- 업무 수행에 필요한 최소 범위
- 필요한 시간 동안만
- 필요한 리소스에만
- 필요한 조건에서만

허용하는 것이다.

즉 범위, 시간, 리소스, 조건까지 함께 줄여야 진짜 Least Privilege다.

### 흔한 오해

- 관리자 권한을 잠깐 주고 나중에 빼면 괜찮다
- 개발 환경이니 넓게 줘도 된다
- 읽기 권한은 위험하지 않다

이 세 가지는 실무에서 자주 깨지는 가정이다.

읽기 권한도 민감 정보 열람과 정찰에 충분히 악용될 수 있다.

## Common IAM Failure Patterns

### 1. Overprivileged Identity

가장 흔한 문제다.

- `*` 리소스
- 광범위한 관리자 권한
- 실제 필요보다 넓은 action 허용

### 2. Forgotten Access Keys

오래된 access key가 방치되는 패턴이다.

코드 저장소, CI 설정, 개인 노트북, 문서에 남기 쉽다.

### 3. Excessive Trust Policy

Role의 trust policy가 과하게 열려 있는 경우다.

결과적으로 의도하지 않은 주체가 역할을 assume할 수 있다.

### 4. PassRole Abuse

특정 역할을 서비스에 넘길 수 있는 권한이 과하게 열려 있으면, 우회적인 privilege escalation이 가능하다.

### 5. Unrestricted Resource Policy

리소스 정책이 너무 넓게 열려 있으면, 정체성 정책을 잘 짜도 리소스 단에서 노출이 생긴다.

### 6. Root Account Misuse

루트 계정을 일상 운영에 쓰는 것은 가장 피해야 할 패턴 중 하나다.

## IAM And Attack Paths

IAM을 공격 관점에서 보면 아래 경로가 자주 등장한다.

1. Access key 탈취
2. MFA 없는 콘솔 계정 탈취
3. 과도한 권한 악용
4. Role assumption 오남용
5. Resource policy 오구성 악용
6. Privilege escalation via IAM action

즉 IAM은 단순 권한표가 아니라, 공격자의 이동 경로이기도 하다.

## Indirect Access Paths

IAM을 공부할 때 자주 놓치는 부분이 있다.  
직접 권한이 없다고 해서 최종 자산에 영향력이 없는 것은 아니다.

예를 들어 아래 구조를 보자.

- 사용자는 `B`에만 접근 가능
- `B`는 `C`에 접근 가능
- `C`는 `A`에 접근 가능

이 경우 사용자는 직접 `A` 권한이 없어도:

1. `B`에 들어가고
2. `B`를 발판으로 `C`에 접근하고
3. `C`가 가진 더 강한 권한이나 연결 경로를 이용해
4. 최종적으로 `A`에 도달할 수 있다

즉 권한은 단순히 "이 사용자에게 A 권한이 있나 없나"로만 보면 안 된다.  
실제로는 `접근 가능한 시스템이 또 다른 권한을 들고 있는가`까지 봐야 한다.

### Why This Happens

간접 접근이 가능해지는 대표적 이유는 아래와 같다.

- 중간 시스템이 더 강한 IAM Role을 가지고 있음
- 중간 시스템에 저장된 자격증명을 재사용할 수 있음
- 중간 시스템에서 다른 시스템으로 명령 실행이 가능함
- 네트워크 경로는 막혀 있지 않지만 IAM은 느슨하게 설계되어 있음
- 서비스 계정이나 워크로드 권한이 과도함

### Example Scenario

예:

- 어떤 사용자는 EC2 인스턴스 `B`에 SSH 가능
- `B` 인스턴스는 Role을 통해 `C` 시스템에 필요한 Secret을 읽을 수 있음
- `C`는 다시 데이터 저장소 `A`에 접근할 수 있음

이 경우 사용자는 직접 `A`에 대한 IAM 권한이 없더라도, `B -> C -> A` 경로를 따라 실질적 영향력을 가질 수 있다.

### How To Think About It

이건 보통 아래 개념과 연결된다.

- Lateral Movement
- Privilege Escalation Path
- Transitive Access
- Attack Path

즉 IAM은 "한 계정의 단독 권한"이 아니라, "정체성, 워크로드, 자격증명, 네트워크 경로가 연결된 그래프"로 봐야 한다.

### What To Check

아래 질문으로 보면 된다.

- 이 주체가 접근 가능한 시스템은 무엇인가
- 그 시스템은 어떤 Role이나 자격증명을 가지고 있는가
- 그 시스템에서 다른 시스템으로 이동 가능한가
- 중간 시스템이 민감 자산에 접근 가능한가
- 직접 권한은 없지만 간접 권한 경로가 생기지 않는가

### Mental Model

IAM 분석은 점 하나를 보는 것이 아니라 그래프를 보는 작업이다.

즉:

`User -> Role -> Workload -> Secret -> Another Role -> Sensitive Resource`

이런 연결이 가능하면, 처음 User에게 직접 권한이 없어도 최종 민감 리소스에 도달할 수 있다.

## Logging And Detection Angle

IAM은 반드시 로그와 같이 봐야 한다.

특히 아래 질문에 답할 수 있어야 한다.

- 누가 로그인했는가
- 실패한 인증이 반복되는가
- 누가 access key를 만들었는가
- 누가 정책을 변경했는가
- 누가 role을 assume 했는가
- 누가 MFA를 비활성화했는가
- 누가 trust policy를 바꿨는가

탐지 포인트 예시:

- 관리자 정책 신규 부여
- 새 access key 생성
- 비정상 지역 로그인
- 평소 안 쓰던 role assumption
- root 계정 사용
- 대량 권한 변경

## Operational Checklist

IAM 운영 상태를 볼 때는 아래를 점검한다.

- 루트 계정에 MFA가 적용되어 있는가
- 사람 계정에 관리자 권한이 직접 붙어 있지 않은가
- 장기 access key가 장기간 방치되고 있지 않은가
- 서비스 간 접근이 role 기반으로 설계되어 있는가
- trust policy가 최소 범위로 제한되어 있는가
- 권한 부여 사유를 설명할 수 있는가
- 미사용 계정과 권한이 정리되고 있는가
- 로그와 감사 추적이 켜져 있는가

## Mental Model To Remember

IAM을 한 문장으로 기억하면 아래 구조다.

`정체성(Identity) + 자격증명(Credential) + 정책(Policy) + 신뢰관계(Trust) + 조건(Condition) = 최종 권한`

이 식이 머리에 들어오면 대부분의 IAM 문제를 구조적으로 해석할 수 있다.

## Day 1 Check

아래를 설명할 수 있으면 기본 구조는 잡힌 것이다.

- User, Group, Role, Policy 차이
- Authentication과 Authorization 차이
- Permission policy와 Trust policy 차이
- 장기 자격증명보다 임시 자격증명이 더 안전한 이유
- Least Privilege가 단순히 "권한 적게 주기"가 아닌 이유
- 명시적 Deny가 왜 중요한지

## Next Deep-Dive Topics

IAM을 더 깊게 보려면 다음 순서가 좋다.

1. `docs/fundamentals/iam/iam-policy-json-anatomy.md`
2. `docs/fundamentals/iam/trust-policy-and-assume-role.md`
3. IAM Privilege Escalation 패턴
4. Federation / SSO 구조
5. AWS IAM, Azure RBAC, GCP IAM 비교
