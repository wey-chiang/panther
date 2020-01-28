---
description: Get started with Panther in 15 minutes
---

# Quick Start

## Concepts

We are excited you are here! Before we cover deployment, let's establish the terminology:

- **Event**: A normalized log line from a sources such as CloudTrail, Osquery, or Suricata
- **Rule**: A Python function to detect suspicious activity
- **Resource**: A cloud entity, such as an IAM user, virtual machine, or data bucket
- **Policy:** A Python function representing the desired secure state of a resource
- **Alert**: A notification to the team when a policy has failed or a rule has triggered

### Prerequisites

_We recommend deploying Panther into its own AWS account via_ [_AWS Organizations_](https://aws.amazon.com/blogs/security/how-to-use-aws-organizations-to-automate-end-to-end-account-creation/)_. This ensures that detection infrastructure is contained within a single place._

You can optionally use Panther alongside an existing logging platform such as Splunk or ElasticSearch. We recommend an architecture that tees traffic between both with tools such as Logstash or Fluentd.

Panther is a collection of serverless applications modeled and deployable with AWS CloudFormation. The frontend is a React application which runs in a Docker container \(via ECS\) and the backend is a collection of Lambda functions, SQS queues, S3 buckets, and more. All infrastructure is designed with least privilege and KMS encryption.

For deployment, you will need an IAM user or role with permission to create resources in Lambda, DynamoDB, S3, ECS, ELB, EC2 \(security groups, subnets, VPC\), SNS, SQS, SES, KMS, IAM, CloudFormation, CloudWatch, API Gateway, Cognito, and AppSync:

{% hint style="info" %}
Precise deployment policy coming soon!
{% endhint %}

```javascript
{"coming": "soon"}
```

### Steps

1. Install [Go](https://golang.org/doc/install#install) 1.13+, [Node](https://nodejs.org/en/download/) 10+, [Python](https://www.python.org/downloads/) 3.7+, and [Docker](https://docs.docker.com/install/) 17+
   - For MacOS w/ homebrew: `brew install go node python3 docker`
2. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html) and [configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) your credentials
   - `pip3 install awscli --upgrade --user && aws configure`
3. Configure your environment
   - `export AWS_REGION=us-east-1 GOPATH=$HOME/go PATH=$PATH:$GOPATH/bin`
   - \(Panther can be deployed to any standard `AWS_REGION`\)
4. Install [Mage](https://magefile.org/#installation): `go get github.com/magefile/mage`
5. Clone the repo to `$GOPATH/src`
   - HTTPS: `git clone https://github.com/panther-labs/panther $GOPATH/src/github.com/panther-labs/panther`
   - SSH: `git clone git@github.com:panther-labs/panther $GOPATH/src/github.com/panther-labs/panther`
6. From the root of the repo, run `mage setup && npm i`
   - `pip` may show warnings about incompatible packages - these are safe to ignore
7. Deploy! `mage deploy`
   - _NOTE: The initial deploy will take 10-15 minutes. If your credentials timeout, you can safely redeploy to pick up where you left off._
8. Configure your initial Panther admin user
   - Near the end of the deploy command, you'll be prompted for first/last name and email
   - You will get an email from [**no-reply@verificationemail.com**](mailto:no-reply@verificationemail.com) with your temporary password. If you don't see it, be sure to check your spam folder.
9. Sign in to Panther! The URL is linked in the welcome email and also printed at the end of the deploy command.
   - _WARNING: By default, Panther generates a self-signed certificate, which will cause most browsers to present a warning page._
   - If you see a "502 Bad Gateway" error, wait a few minutes and refresh the page

## Onboarding

Follow the steps below to onboard data, add AWS accounts, configure alert destinations, and more. The first step is configuring your [alert outputs](destinations/alert-setup/). Then, proceed below to configure scans and real-time log analysis.

#### Log Analysis

- [Log Analysis Setup](log-analysis/log-processing/)
- [Create Rules for supported Log Types](log-analysis/rules/)

#### Cloud Compliance

- [Background](policies/compliance-background.md)
- [Compliance Scanning Setup](policies/scanning/)
- [Create Policies](policies/compliance-background.md) for the supported [AWS Resources](policies/resources/)

## **Support**

- [Report Bugs](https://github.com/panther-labs/panther/issues)
- [Chat with the Panther Labs team on Gitter](https://gitter.im/runpanther/community)
- [Panther Blog](https://blog.runpanther.io/)
- [Panther Website](https://runpanther.io/)