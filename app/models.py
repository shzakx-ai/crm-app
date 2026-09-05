"""Pydantic schemas — strict input validation for API bodies."""
from typing import Optional

from pydantic import BaseModel, Field, field_validator


def _validate_email(cls, v):
    if v is None or v == "":
        return v
    if "@" not in v or "." not in v.split("@")[-1]:
        raise ValueError(f"Invalid email address: {v}")
    return v


class ContactBase(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="", max_length=50)
    email: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: str = Field(default="lead", pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _validate_email(cls, v)


class ContactCreate(ContactBase):
    pass


class ContactUpdate(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    email: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: Optional[str] = Field(default=None, pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _validate_email(cls, v)


class DealCreate(BaseModel):
    contact_id: int
    title: str = Field(..., min_length=1, max_length=200)
    value: float = Field(0, ge=0)
    currency: str = Field(default="EUR", max_length=10)
    stage: str = Field(default="lead", pattern=r"^(lead|qualified|proposal|negotiation|won|lost)$")
    expected_close: Optional[str] = Field(default=None, max_length=20)
    notes: Optional[str] = Field(default=None, max_length=1000)


class DealUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    value: Optional[float] = Field(default=None, ge=0)
    currency: Optional[str] = Field(default=None, max_length=10)
    stage: Optional[str] = Field(default=None, pattern=r"^(lead|qualified|proposal|negotiation|won|lost)$")
    expected_close: Optional[str] = Field(default=None, max_length=20)
    notes: Optional[str] = Field(default=None, max_length=1000)


class ActivityCreate(BaseModel):
    contact_id: int
    deal_id: Optional[int] = None
    type: str = Field(default="note", pattern=r"^(note|call|email|meeting|task)$")
    subject: str = Field(default="", max_length=200)
    body: str = Field(default="", max_length=2000)
    due_date: str = Field(default="", max_length=20)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="member", pattern=r"^(admin|member)$")