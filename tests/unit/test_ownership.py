from s3_auditor.checks.ownership import check_bucket


class FakeS3Client:
    def get_bucket_ownership_controls(self, Bucket):
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}}


def test_ownership_flags_missing_enforced_setting():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-007"
    assert result["status"] == "FAIL"
