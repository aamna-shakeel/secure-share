from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    password_confirmation: str = Field(min_length=12, max_length=128)

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.password_confirmation:
            raise ValueError("passwords do not match")
        return self


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    created_at: datetime


class MessageResponse(BaseModel):
    message: str


class DocumentResponse(BaseModel):
    id: int
    owner_id: int
    original_filename: str
    content_type: str
    file_size: int
    created_at: datetime
    access: str


class ShareCreateRequest(BaseModel):
    email: EmailStr


class ShareResponse(BaseModel):
    id: int
    document_id: int
    shared_with_user_id: int
    shared_with_email: EmailStr
    created_at: datetime
    revoked_at: datetime | None


class LinkCreateRequest(BaseModel):
    expires_in_seconds: int | None = Field(default=None, ge=60, le=2_592_000)


class LinkResponse(BaseModel):
    id: int
    document_id: int
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class NewLinkResponse(LinkResponse):
    url: str
