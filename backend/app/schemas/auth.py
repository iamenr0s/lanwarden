from typing import Annotated

from pydantic import BaseModel, Field

Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")]


class Credentials(BaseModel):
    username: Username
    password: Annotated[str, Field(min_length=1, max_length=256)]


NewPassword = Annotated[str, Field(min_length=10, max_length=256)]


class SetupRequest(BaseModel):
    username: Username
    password: NewPassword
    setup_token: Annotated[str | None, Field(max_length=256)] = None  # required when LANWARDEN_SETUP_TOKEN is set


class PasswordChange(BaseModel):
    current_password: Annotated[str, Field(min_length=1, max_length=256)]
    new_password: NewPassword


class AuthState(BaseModel):
    setup_required: bool
    setup_token_required: bool = False
    insecure_transport: bool = False  # plain HTTP to a non-loopback host
    authenticated: bool
    username: str | None = None
    mfa_enabled: bool = False
    mfa_enrolment_required: bool = False  # server demands MFA and this account has none yet
    # Returned by /login for MFA accounts instead of a session; exchange it at /login/mfa with a code.
    mfa_required: bool = False
    mfa_token: str | None = None


class MfaLogin(BaseModel):
    mfa_token: Annotated[str, Field(min_length=1, max_length=1024)]
    code: Annotated[str, Field(min_length=1, max_length=64)]  # 6-digit TOTP, or a recovery code


class MfaPassword(BaseModel):
    password: Annotated[str, Field(min_length=1, max_length=256)]


class MfaSetupOut(BaseModel):
    secret: str  # shown once, for manual entry
    otpauth_uri: str  # for the QR code


class MfaEnable(BaseModel):
    code: Annotated[str, Field(min_length=6, max_length=12)]


class MfaConfirm(BaseModel):
    password: Annotated[str, Field(min_length=1, max_length=256)]
    code: Annotated[str, Field(min_length=1, max_length=64)]


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]  # shown once; only hashes are stored
