data "aws_iam_policy_document" "lbc_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lbc" {
  name               = "ebpf-shield-lbc"
  assume_role_policy = data.aws_iam_policy_document.lbc_trust.json
}

resource "aws_iam_policy" "lbc" {
  name   = "ebpf-shield-lbc-policy"
  policy = file("${path.module}/lbc_policy.json")
}

resource "aws_iam_role_policy_attachment" "lbc" {
  role       = aws_iam_role.lbc.name
  policy_arn = aws_iam_policy.lbc.arn
}

resource "aws_eks_pod_identity_association" "lbc" {
  cluster_name    = module.eks.cluster_name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.lbc.arn

  depends_on = [aws_iam_role_policy_attachment.lbc]
}
