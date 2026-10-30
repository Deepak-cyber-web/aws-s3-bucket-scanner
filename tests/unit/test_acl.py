from s3_auditor.checks.acl import check_bucket


class FakeS3Client:
    def get_bucket_acl(self, Bucket):
        return {
            "Grants": [
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
            ]
        }


def test_acl_flags_public_grants():
    result = check_bucket(FakeS3Client(), "demo-bucket")
    assert result["finding_id"] == "S3-003"
    assert result["status"] == "FAIL"
    assert result["severity"] == "HIGH"
