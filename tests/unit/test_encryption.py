from s3_auditor.checks.encryption import check_bucket


class FakeS3Client:
    def get_bucket_encryption(self, Bucket):
        raise Exception("Simulated missing encryption error")


def test_encryption_handles_missing_bucket_encryption():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-004"
    assert result["status"] == "FAIL"
