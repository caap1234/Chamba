from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    email: str = Field(..., min_length=5, max_length=160)
    full_name: str = Field(..., min_length=2, max_length=160)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst", pattern="^(admin|supervisor|analyst|readonly)$")
    allowed_orgs: List[str] = Field(default_factory=lambda: ["NBX", "HP"])
    iris_user_id: Optional[int] = 2


class UserUpdateRequest(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = Field(default=None, pattern="^(admin|supervisor|analyst|readonly)$")
    allowed_orgs: Optional[List[str]] = None
    is_active: Optional[bool] = None
    iris_user_id: Optional[int] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    allowed_orgs: List[str]
    iris_user_id: Optional[int] = None
    is_active: bool
    last_login_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

