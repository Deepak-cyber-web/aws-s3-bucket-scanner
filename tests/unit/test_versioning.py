from s3_auditor.checks.versioning import check_bucket


class FakeS3Client:
    def get_bucket_versioning(self, Bucket):
        return {"Status": "Suspended"}


def test_versioning_detects_disabled_state():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-005"
    assert result["status"] == "FAIL"
