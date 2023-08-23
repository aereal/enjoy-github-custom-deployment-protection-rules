terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.13.1"
    }
  }
}

provider "aws" {}

locals {
  function_name = "gh-custom-deploy-protection"
}

resource "aws_lambda_function_url" "webhook" {
  function_name      = local.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "allow_invoke_from_url" {
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = local.function_name
  function_url_auth_type = "NONE"
  principal              = "*"
}

resource "aws_ecr_repository" "webhook" {
  name = local.function_name
}

data "aws_iam_policy_document" "allow_pull_from_lambda" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
  }
}

resource "aws_ecr_repository_policy" "webhook" {
  repository = aws_ecr_repository.webhook.name
  policy     = data.aws_iam_policy_document.allow_pull_from_lambda.json
}

resource "aws_cloudwatch_log_group" "webhook" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 7
}

data "aws_iam_policy_document" "allow_assume_from_lambda" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "webhook" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "xray:GetSamplingRules",
      "xray:GetSamplingStaticticSummaries",
      "xray:GetSamplingTargets",
      "xray:PutTelemetryRecords",
      "xray:PutTraceSegments",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "webhook" {
  name   = local.function_name
  policy = data.aws_iam_policy_document.webhook.json
}

resource "aws_iam_role" "webhook" {
  name               = local.function_name
  assume_role_policy = data.aws_iam_policy_document.allow_assume_from_lambda.json
}

resource "aws_iam_role_policy_attachment" "webhook" {
  role       = aws_iam_role.webhook.name
  policy_arn = aws_iam_policy.webhook.arn
}
