# IAM Policy JSON Anatomy

## Goal

이 문서는 AWS IAM Policy JSON을 구조적으로 읽고 해석하는 데 집중한다. 목표는 단순히 문법을 아는 수준이 아니라, JSON 한 덩어리를 봤을 때 권한 범위, 위험성, 설계 의도를 빠르게 파악할 수 있게 되는 것이다.

## Why This Matters

IAM은 결국 정책 문서로 권한이 결정된다. 콘솔에서 체크박스를 눌러도 내부적으로는 JSON 정책이 만들어진다.

즉 IAM을 깊게 이해하려면 결국 아래 질문에 답할 수 있어야 한다.

1. 이 JSON은 무엇을 허용하거나 거부하는가
2. 누구에게 적용되는가
3. 어디에 적용되는가
4. 어떤 조건이 붙어 있는가
5. 위험한 와일드카드나 과도한 허용이 있는가

## The Basic Shape

가장 기본적인 IAM 정책 구조는 아래처럼 생긴다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExampleStatement",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
```

핵심 필드는 다음이다.

- `Version`
- `Statement`
- `Sid`
- `Effect`
- `Action`
- `Resource`
- `Condition`
- `Principal`

## Version

`Version`은 정책 문서 문법 버전을 나타낸다.

가장 자주 보는 값은 아래다.

```json
"Version": "2012-10-17"
```

이 값은 "이 정책이 언제 만들어졌는가"라는 뜻이 아니라, 정책 언어 버전을 뜻한다.

## Statement

실제 권한 규칙은 `Statement` 안에 들어 있다.

중요한 점:

- Policy 하나 안에는 여러 `Statement`가 들어갈 수 있다
- 각 `Statement`는 독립적인 규칙 단위다

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

즉 하나의 정책 문서 안에 허용과 거부 규칙을 함께 넣을 수 있다.  
하지만 각 `Statement`는 `Effect`를 하나만 가진다.

## Sid

`Sid`는 Statement ID다. 사람이 읽기 쉽게 규칙 이름을 붙이는 용도다.

예:

```json
"Sid": "AllowReadOnlyToReportsBucket"
```

권한 동작 자체를 바꾸지는 않지만, 정책을 나중에 읽고 감사할 때 큰 도움이 된다.

좋은 `Sid`는 아래처럼 의도가 드러나야 한다.

- `AllowCloudTrailReadOnly`
- `DenyOutsideApprovedRegion`
- `AllowAssumeRoleFromSecurityAccount`

## Effect

`Effect`는 허용 또는 거부를 나타낸다.

가능한 값:

- `Allow`
- `Deny`

중요한 원칙:

1. 기본값은 거부다
2. 명시적 Allow가 있어야 허용된다
3. 명시적 Deny는 Allow보다 우선한다

예:

```json
"Effect": "Allow"
```

또는

```json
"Effect": "Deny"
```

한 Statement 안에 여러 개 Effect를 넣을 수는 없다.

## Action

`Action`은 어떤 행위를 허용하거나 거부하는지 나타낸다.

예:

```json
"Action": "s3:GetObject"
```

여러 개를 줄 수도 있다.

```json
"Action": [
  "s3:GetObject",
  "s3:ListBucket"
]
```

와일드카드도 가능하다.

```json
"Action": "s3:*"
```

또는

```json
"Action": "*"
```

### Reading Action Carefully

`Action`은 얼핏 비슷해 보여도 의미가 다르다.

예:

- `s3:GetObject`
  객체 읽기
- `s3:ListBucket`
  버킷 목록 조회
- `iam:PassRole`
  서비스에 역할을 넘길 수 있는 권한

특히 `iam:*`, `sts:*`, `kms:*`, `organizations:*` 같은 민감 서비스는 더 조심해서 봐야 한다.

## Resource

`Resource`는 권한이 적용되는 대상을 뜻한다.

예:

```json
"Resource": "arn:aws:s3:::example-bucket/*"
```

여러 리소스도 가능하다.

```json
"Resource": [
  "arn:aws:s3:::example-bucket",
  "arn:aws:s3:::example-bucket/*"
]
```

전체 리소스를 뜻하는 와일드카드도 가능하다.

```json
"Resource": "*"
```

### Why Resource Matters

같은 Action이라도 Resource 범위에 따라 위험도가 완전히 달라진다.

예:

- 특정 버킷 하나만 읽기
- 모든 버킷 읽기
- 모든 리소스에 대해 모든 작업 허용

이 세 가지는 전혀 다르다.

따라서 정책을 읽을 때는 항상 `Action`과 `Resource`를 붙여서 읽어야 한다.

## Principal

`Principal`은 누가 이 정책의 대상이 되는지를 나타낸다.

이 필드는 주로 아래 정책에서 중요하다.

- Trust Policy
- Resource-Based Policy

예:

```json
"Principal": {
  "Service": "ec2.amazonaws.com"
}
```

또는:

```json
"Principal": {
  "AWS": "arn:aws:iam::111122223333:role/SecurityAuditRole"
}
```

### Dangerous Principal Patterns

가장 조심해야 할 패턴 중 하나는 아래다.

```json
"Principal": "*"
```

이건 리소스 정책이나 trust policy에서 매우 위험할 수 있다.  
누구나 접근 가능하다는 뜻으로 이어질 수 있기 때문이다.

## Condition

`Condition`은 권한이 작동하는 추가 조건이다.

예:

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  }
}
```

즉 이 Statement는 "MFA가 있을 때만" 적용된다.

### Common Condition Uses

보통 아래 조건이 자주 나온다.

- MFA 여부
- Source IP 제한
- 특정 리전 제한
- 특정 태그 기반 제한
- 특정 시간대 제한
- 특정 VPC Endpoint 조건

예시 1. MFA 조건:

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  }
}
```

예시 2. 리전 제한:

```json
"Condition": {
  "StringEquals": {
    "aws:RequestedRegion": "ap-northeast-2"
  }
}
```

예시 3. IP 제한:

```json
"Condition": {
  "IpAddress": {
    "aws:SourceIp": "203.0.113.0/24"
  }
}
```

### Condition Operators

자주 보는 연산자는 아래와 같다.

- `StringEquals`
- `StringNotEquals`
- `Bool`
- `IpAddress`
- `NotIpAddress`
- `NumericLessThan`
- `DateGreaterThan`
- `ArnEquals`

정책을 읽을 때는 연산자 이름을 먼저 보면 된다.

- `Equals`
  같아야 함
- `NotEquals`
  다를 때 적용
- `IpAddress`
  특정 IP 범위일 때 적용

## NotAction And NotResource

심화 정책에서 자주 헷갈리는 부분이다.

### NotAction

`NotAction`은 "이 액션을 제외한 나머지"라는 뜻이다.

예:

```json
{
  "Effect": "Deny",
  "NotAction": "iam:List*",
  "Resource": "*"
}
```

이런 식의 문서는 읽기 어렵고, 잘못 해석하면 위험해질 수 있다.

### NotResource

`NotResource`는 "이 리소스를 제외한 나머지"라는 뜻이다.

역시 표현력은 강하지만 직관성이 떨어지기 때문에 실무에서 신중히 써야 한다.

## Identity Policy vs Trust Policy vs Resource Policy

같은 JSON처럼 보여도 역할이 다르다.

### Identity-Based Policy

주체에게 붙는 정책이다.

질문:

`이 주체가 무엇을 할 수 있는가`

예:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket",
        "arn:aws:s3:::example-bucket/*"
      ]
    }
  ]
}
```

### Trust Policy

Role에 붙으며, 누가 그 역할을 맡을 수 있는지 정한다.

질문:

`누가 이 역할을 assume할 수 있는가`

예:

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

여기서는 `Resource`보다 `Principal`이 핵심이다.

### Resource-Based Policy

리소스에 붙는 정책이다.

질문:

`누가 이 리소스에 접근할 수 있는가`

예:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
```

## Reading Order

IAM Policy JSON은 아래 순서로 읽으면 해석이 빨라진다.

1. `Effect`
허용인지 거부인지 먼저 본다.

2. `Action` 또는 `NotAction`
무슨 행위에 대한 규칙인지 본다.

3. `Resource` 또는 `NotResource`
대상이 특정 자원인지 전체인지 본다.

4. `Principal`
누가 대상인지 본다. trust/resource policy일 때 특히 중요하다.

5. `Condition`
IP, MFA, 리전, 태그 등 추가 제한이 있는지 본다.

6. 와일드카드
`*`가 많은지 확인한다.

## Example Dissection

아래 정책을 한 줄씩 읽어보자.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadFromOneBucketWithMFA",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-reports",
        "arn:aws:s3:::company-reports/*"
      ],
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

이 정책은 다음 의미다.

- `Allow`
  허용 규칙이다
- `s3:GetObject`, `s3:ListBucket`
  읽기 관련 액션만 허용한다
- `company-reports`
  특정 버킷에만 적용된다
- `MFA true`
  MFA가 있을 때만 허용된다

즉 "MFA가 있는 사용자만 특정 버킷 읽기 허용"이라고 정리할 수 있다.

## How Deny Works In JSON

기본값은 거부다. 하지만 명시적 `Deny`는 이미 있는 `Allow`도 덮어쓴다.

예:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRunInstances",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    },
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

이 정책은:

- 기본적으로 인스턴스 생성을 허용하지만
- 서울 리전이 아닌 곳에서는 명시적으로 막는다

는 뜻이다.

즉 `Deny`는 단독으로 허용을 만드는 것이 아니라, 기존 허용 범위를 잘라내는 데 자주 사용된다.

## Wildcards And Risk

JSON 정책에서 가장 위험 신호가 잘 드러나는 부분은 와일드카드다.

### Action Wildcards

```json
"Action": "s3:*"
```

특정 서비스 전체 액션 허용이다.

```json
"Action": "*"
```

사실상 모든 서비스 액션을 의미한다.

### Resource Wildcards

```json
"Resource": "*"
```

모든 리소스를 의미한다.

### Principal Wildcards

```json
"Principal": "*"
```

누구나 대상이 될 수 있음을 뜻할 수 있다.

### High-Risk Combination

아래 패턴은 매우 위험하다.

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

이건 사실상 관리자 권한에 매우 가깝다.

## Common Dangerous JSON Patterns

### 1. Full Admin Style Policy

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### 2. Trust Policy With Broad Principal

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "sts:AssumeRole"
}
```

누구나 역할을 맡을 수 있는 구조로 이어질 수 있다.

### 3. Resource Policy Open To Entire Account Or World

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::example-bucket/*"
}
```

이건 공개 접근으로 이어질 수 있다.

### 4. Overly Broad IAM Actions

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:*",
    "sts:*"
  ],
  "Resource": "*"
}
```

권한 상승 경로로 이어질 수 있다.

## Safe Reading Checklist

정책 JSON을 볼 때는 아래 체크리스트로 보면 된다.

- `Effect`가 Allow인가 Deny인가
- `Action` 범위가 너무 넓지 않은가
- `Resource`가 `*`인지 특정 ARN인지
- `Principal`이 너무 넓지 않은가
- `Condition`이 전혀 없는가
- `iam:PassRole`, `sts:AssumeRole`, `kms:*` 같은 민감 액션이 있는가
- `NotAction`, `NotResource`처럼 해석이 어려운 표현이 있는가

## Mental Model

정책 JSON을 한 문장으로 읽는 습관을 들이면 좋다.

예를 들어 아래처럼 번역한다.

`누가(Principal), 어떤 조건에서(Condition), 어떤 행동을(Action), 어떤 대상(Resource)에 대해, 허용 또는 거부(Effect)하는가`

이 순서로 자연어로 바꿔 읽으면 JSON이 훨씬 덜 복잡하게 느껴진다.

## Suggested Next Step

이 문서 다음에는 아래 주제로 이어가는 것이 좋다.

1. Trust Policy와 AssumeRole 흐름
2. IAM Privilege Escalation 패턴
3. Resource Policy와 Identity Policy 충돌 사례
