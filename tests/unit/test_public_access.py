from s3_auditor.checks.public_access import check_bucket


class FakeS3Client:
    def get_public_access_block(self, Bucket):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }


def test_public_access_fails_when_configuration_is_not_fully_enforced():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-001"
    assert result["status"] == "FAIL"
    assert result["severity"] == "HIGH"
