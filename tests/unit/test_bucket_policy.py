from s3_auditor.checks.bucket_policy import check_bucket


class FakeS3Client:
    def get_bucket_policy(self, Bucket):
        return {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo-bucket/*"}]}'
        }


def test_bucket_policy_finds_public_access():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-002"
    assert result["status"] == "FAIL"
    assert result["severity"] == "CRITICAL"
