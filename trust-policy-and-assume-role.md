# Trust Policy And AssumeRole Flow

## Goal

이 문서는 AWS IAM에서 `Trust Policy`와 `AssumeRole` 흐름을 깊게 이해하기 위한 문서다. 목표는 단순히 "Role을 맡는다"는 수준이 아니라, 누가 어떤 조건에서 역할을 맡을 수 있는지, 그 결과 어떤 임시 자격증명이 생기는지, 어디서 위험이 생기는지를 설명할 수 있게 되는 것이다.

## Why This Matters

IAM에서 가장 많이 헷갈리는 부분 중 하나가 바로 `Permission Policy`와 `Trust Policy`의 차이다.

많은 사람이 Role을 이렇게만 이해한다.

- Role에는 권한이 있다
- 누군가 그 Role을 사용한다

이건 반만 맞다.

실제로는 아래 두 가지가 동시에 필요하다.

1. 누가 그 역할을 맡을 수 있는가
2. 그 역할을 맡은 뒤 무엇을 할 수 있는가

즉 Role은 항상 아래 두 축으로 봐야 한다.

- `Trust Policy`
  누가 이 Role을 assume할 수 있는가
- `Permission Policy`
  이 Role을 맡은 뒤 무엇을 할 수 있는가

## The Simple Mental Model

Trust Policy는 `입장권`이고, Permission Policy는 `입장 후 행동 범위`다.

즉:

- Trust Policy가 열려 있어야 Role을 맡을 수 있고
- Permission Policy가 있어야 실제 행동을 할 수 있다

둘 중 하나만 봐서는 안 된다.

## A Common Misunderstanding

처음 IAM을 볼 때 많은 사람이 `Trust Policy`와 `Permission Policy`를 완전히 다른 세계의 정책이라고 생각한다.

하지만 실무에서는 보통 `하나의 Role`을 볼 때 이 둘을 함께 본다.

즉 Role 하나를 이해할 때는 아래 두 질문을 동시에 봐야 한다.

1. 누가 이 Role을 맡을 수 있는가
2. 이 Role을 맡은 뒤 무엇을 할 수 있는가

다시 말하면:

- `Trust Policy`
  이 Role의 입장 조건
- `Permission Policy`
  이 Role의 행동 범위

이다.

그래서 이 둘은 서로 별개 개념이지만, 운영과 분석에서는 같은 Role의 앞면과 뒷면처럼 같이 다뤄야 한다.

### One Role, Two Policies

예를 들어 `EC2AppRole`이 있다고 하면, 그 Role을 볼 때 보통 같이 보는 것은 아래 두 가지다.

#### 1. Trust Policy

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

의미:

`EC2 서비스는 이 Role을 맡을 수 있다`

#### 2. Permission Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::app-config-bucket/*"
    }
  ]
}
```

의미:

`이 Role을 맡은 주체는 특정 버킷을 읽을 수 있다`

즉 이 두 정책은 서로 다른 목적을 가지지만, 같은 Role을 설명하는 데 함께 필요하다.

## What Is AssumeRole

`AssumeRole`은 어떤 주체가 특정 Role을 맡아 임시 자격증명을 발급받는 과정이다.

쉽게 말하면:

1. 누군가 Role을 맡고 싶어 한다
2. AWS는 trust policy를 보고 그게 허용되는지 확인한다
3. 허용되면 임시 자격증명을 발급한다
4. 그 주체는 그 임시 자격증명으로 요청을 보낸다
5. 그때는 Role의 permission policy 기준으로 권한이 평가된다

즉 AssumeRole은 "역할 전환"과 "임시 자격증명 발급"이 합쳐진 흐름이다.

## Trust Policy Deep Dive

Trust Policy는 Role에 붙는 특별한 정책이다.

핵심 질문:

`누가 이 역할을 맡을 수 있는가`

보통 trust policy에서는 아래 요소가 중요하다.

- `Effect`
- `Principal`
- `Action`
- `Condition`

### Basic Example

아래 예시는 EC2 서비스가 특정 Role을 맡을 수 있게 하는 trust policy다.

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

이 JSON의 의미:

- `Principal`
  EC2 서비스가
- `Action`
  `sts:AssumeRole`을 통해
- `Effect`
  이 Role을 맡는 것을 허용한다

즉 이건 "EC2가 이 역할을 사용할 수 있다"는 뜻이다.

### Principal In Trust Policy

Trust Policy에서 가장 중요한 것은 `Principal`이다.

대표 형태:

- `Service`
- `AWS`
- `Federated`

예:

```json
"Principal": {
  "Service": "lambda.amazonaws.com"
}
```

```json
"Principal": {
  "AWS": "arn:aws:iam::111122223333:role/SecurityAuditRole"
}
```

```json
"Principal": {
  "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
}
```

즉 trust policy는 누가 들어올 수 있는지 정하는 문이고, `Principal`은 그 문의 대상이다.

## Permission Policy Deep Dive

Role에 붙는 permission policy는 아래 질문에 답한다.

`이 Role을 맡은 뒤 무엇을 할 수 있는가`

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
        "arn:aws:s3:::company-reports",
        "arn:aws:s3:::company-reports/*"
      ]
    }
  ]
}
```

이 정책은 "그 Role을 맡은 뒤 특정 버킷을 읽을 수 있다"는 뜻이다.

핵심은 다음이다.

- Trust Policy는 Role을 맡을 수 있게 함
- Permission Policy는 맡은 뒤 행동을 허용함

## End-To-End Flow

AssumeRole 흐름은 보통 아래처럼 생각하면 된다.

1. 주체가 존재한다
예:
- 사람
- EC2
- Lambda
- 다른 AWS 계정의 Role

2. 주체가 특정 Role을 assume하려고 한다

3. AWS가 Role의 trust policy를 평가한다

4. 허용되면 임시 자격증명을 발급한다

5. 이후 요청은 그 임시 자격증명으로 이루어진다

6. 그 요청은 Role의 permission policy 기준으로 평가된다

즉 AssumeRole은 `사전 입장 검사`와 `사후 행동 권한`이 분리된 구조다.

## Example 1. EC2 AssumeRole

### Trust Policy

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

### Permission Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::app-config-bucket/*"
    }
  ]
}
```

해석:

- EC2는 이 Role을 맡을 수 있다
- 이 Role을 맡은 EC2는 특정 버킷의 객체를 읽을 수 있다

즉 EC2 인스턴스 자체가 장기 access key 없이도 S3를 읽을 수 있게 된다.

## EC2, Instance Profile, Role

여기서 가장 많이 헷갈리는 포인트가 있다.

`ec2.amazonaws.com`을 trust policy에 넣었다고 해서, 그 Role이 모든 EC2에 자동으로 붙는 것은 아니다.

이 trust policy의 의미는 단지:

`EC2 서비스는 이 Role을 사용할 자격이 있다`

는 뜻이다.

즉 trust policy는 자동 부착을 의미하지 않는다.

### What Actually Happens

EC2에서 Role이 동작하려면 보통 아래 흐름이 필요하다.

1. EC2용 Role을 만든다
2. trust policy에 `ec2.amazonaws.com`을 넣는다
3. 그 Role을 instance profile에 연결한다
4. EC2 인스턴스를 생성할 때 그 instance profile을 붙인다
5. 인스턴스 안의 애플리케이션이 필요할 때 임시 자격증명을 받는다

즉 실제 구조는 아래처럼 이해하면 된다.

`EC2 -> Instance Profile -> Role -> Temporary Credential`

### What Is Instance Profile

`Instance Profile`은 EC2가 IAM Role을 사용할 수 있게 연결해주는 중간 객체다.

중요한 점:

- 권한은 Role에 있다
- EC2는 그 Role을 직접 붙이는 것처럼 보이지만
- 실제로는 instance profile을 통해 연결된다

즉 instance profile은 권한 자체가 아니라, EC2와 Role을 연결하는 포장지나 컨테이너에 가깝다.

### Why This Matters

EC2에서 Role이 안 먹는 상황은 보통 아래 셋 중 하나다.

1. permission policy가 원하는 액션을 허용하지 않음
2. trust policy에 `ec2.amazonaws.com`이 없음
3. instance profile이 실제 인스턴스에 붙어 있지 않음

즉 trust policy만 맞아도 안 되고, 실제 연결(instance profile)까지 되어야 한다.

### Mental Model

비유로 보면:

- Role
  권한이 적힌 카드
- Trust Policy
  EC2가 그 카드를 쓸 자격이 있다는 규칙
- Instance Profile
  그 카드를 특정 EC2에게 전달하는 카드 홀더

즉 trust policy는 사용 자격이고, instance profile은 실제 부착 수단이다.

## Example 2. Cross-Account AssumeRole

다른 AWS 계정의 Role이 내 계정의 Role을 assume하게 만들 수도 있다.

### Trust Policy

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

해석:

- 다른 계정 `111122223333`의 `SecurityAuditRole`만
- 이 Role을 맡을 수 있다

이런 구조는 중앙 보안 계정이 여러 계정을 감사할 때 자주 쓴다.

## Example 3. Federated User AssumeRole

기업 SSO 사용자가 federated identity를 통해 Role을 맡는 구조도 흔하다.

### Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
      },
      "Action": "sts:AssumeRoleWithSAML"
    }
  ]
}
```

이건 "특정 SAML 제공자를 통해 인증된 사용자가 이 Role을 맡을 수 있다"는 뜻이다.

## Condition In Trust Policy

Trust policy에도 `Condition`을 붙일 수 있다.

이건 매우 중요하다.  
왜냐하면 `Principal`만 좁히는 것보다 더 세밀한 통제가 가능하기 때문이다.

예:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/DeploymentRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "corp-prod-deploy"
        }
      }
    }
  ]
}
```

이 예시의 의미:

- 특정 외부 Role만 들어올 수 있고
- 추가로 `ExternalId`가 맞아야만 assume 가능

즉 신뢰관계를 더 좁히는 방식이다.

## What Credentials Are Created

AssumeRole이 성공하면 보통 아래 임시 자격증명이 생긴다.

- Access Key ID
- Secret Access Key
- Session Token
- Expiration

즉 장기 비밀이 아니라, 수명이 있는 임시 세션이 생긴다.

이게 중요한 이유:

- 장기 자격증명을 줄일 수 있음
- 세션 만료가 있음
- 누가 어떤 Role을 언제 맡았는지 추적 가능

## Common Confusions

### Confusion 1. Trust Policy가 있으면 바로 권한이 생기나

아니다.

Trust policy는 "맡을 수 있는가"만 정한다.  
실제 권한은 permission policy가 정한다.

### Confusion 2. Permission Policy만 넓으면 누구나 그 Role을 쓰나

아니다.

아무리 권한이 넓어도 trust policy가 막고 있으면 assume할 수 없다.

### Confusion 3. AssumeRole은 권한 복사인가

완전히 그렇지는 않다.

원래 주체의 권한을 그대로 복사하는 것이 아니라, Role을 맡은 세션으로 동작하게 된다.

즉 이후 요청은 Role 기준으로 평가된다.

## Dangerous Patterns

### 1. Broad Principal In Trust Policy

아래 같은 구조는 매우 위험할 수 있다.

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "sts:AssumeRole"
}
```

누가 들어올 수 있는지 지나치게 넓게 열어둔 구조다.

### 2. Trust Policy Too Broad At Account Level

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:root"
  },
  "Action": "sts:AssumeRole"
}
```

이건 특정 계정 전체를 신뢰하는 구조라서, 그 계정 안의 어떤 주체가 실질적으로 들어올 수 있는지 더 주의해서 봐야 한다.

### 3. Overpowered Permission Policy

trust policy는 좁게 잡았더라도, 맡은 뒤 권한이 지나치게 넓으면 결국 위험하다.

예:

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### 4. PassRole Abuse

어떤 주체가 서비스에 특정 Role을 넘길 수 있는 권한이 있으면, 직접 assume하지 않더라도 우회적인 권한 상승이 가능해질 수 있다.

즉 `iam:PassRole`은 trust policy와 함께 봐야 한다.

## Attack Path View

AssumeRole은 공격자 관점에서도 매우 중요하다.

공격 경로 예:

1. 낮은 권한 User를 탈취한다
2. 그 User가 어떤 Role을 assume할 수 있는지 본다
3. 더 강한 Role로 점프한다
4. 그 Role로 다시 다른 서비스나 리소스에 접근한다

즉 IAM 분석에서는 항상 아래를 같이 봐야 한다.

- 누가 어떤 Role을 맡을 수 있는가
- 맡은 뒤 무엇을 할 수 있는가
- 그 Role을 다시 다른 공격 단계의 발판으로 쓸 수 있는가

## How To Review A Trust Policy

Trust policy를 볼 때는 아래 순서로 보면 된다.

1. `Principal`이 누구인가
2. 너무 넓은가, 너무 좁은가
3. `Action`이 정확히 `sts:AssumeRole` 계열인가
4. `Condition`이 있는가
5. cross-account라면 외부 계정 전체를 여는지, 특정 Role만 여는지
6. 이 Role의 permission policy는 얼마나 강한가

즉 trust policy는 단독으로 보지 말고, 반드시 permission policy와 같이 봐야 한다.

## Mental Model

AssumeRole 흐름은 아래 문장으로 기억하면 된다.

`Trust Policy가 입장을 허용하고, STS가 임시 자격증명을 발급하고, Permission Policy가 이후 행동 범위를 결정한다`

이 문장만 정확히 이해해도 Role 구조가 훨씬 선명해진다.

## Suggested Next Step

이 문서 다음에는 아래 주제로 이어가는 것이 자연스럽다.

1. IAM Privilege Escalation 패턴
2. `iam:PassRole`과 service role 오남용
3. Cross-account trust 설계 패턴
