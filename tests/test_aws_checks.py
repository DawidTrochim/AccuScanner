from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from mininessus.aws_checks import _check_iam_users_without_mfa, _check_stale_iam_access_keys


class _IamClient:
    def list_users(self):
        return {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}

    def list_mfa_devices(self, UserName: str):
        return {"MFADevices": [] if UserName == "alice" else [{"SerialNumber": "mfa-device"}]}

    def get_login_profile(self, UserName: str):
        if UserName == "alice":
            return {"LoginProfile": {"UserName": "alice"}}
        from botocore.exceptions import ClientError

        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

    def list_access_keys(self, UserName: str):
        age = datetime.now(UTC) - timedelta(days=120 if UserName == "alice" else 30)
        return {
            "AccessKeyMetadata": [
                {"AccessKeyId": f"AKIA{UserName.upper()}", "CreateDate": age}
            ]
        }


class _IamClientNoProfile(_IamClient):
    def get_login_profile(self, UserName: str):
        from botocore.exceptions import ClientError

        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")


class _Session:
    def __init__(self, client):
        self._client = client

    def client(self, service_name: str):
        assert service_name == "iam"
        return self._client


def test_check_iam_users_without_mfa_flags_console_user(monkeypatch):
    findings = list(_check_iam_users_without_mfa(_Session(_IamClient())))
    assert any(finding.id == "AWS-IAM-003" and finding.target == "alice" for finding in findings)


def test_check_stale_iam_access_keys_flags_old_keys():
    findings = list(_check_stale_iam_access_keys(_Session(_IamClientNoProfile())))
    assert any(finding.id == "AWS-IAM-004" and finding.target == "alice" for finding in findings)
