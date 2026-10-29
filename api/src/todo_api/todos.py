"""The todo list: in memory, lost on restart. Each caller (token `sub`) has their own list."""
from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class TodoCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    done: bool = False


class TodoUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    done: Optional[bool] = None


class Todo(BaseModel):
    id: UUID
    title: str
    done: bool
    created_at: datetime


class TodoStore:
    def __init__(self) -> None:
        self._lock = Lock()  # FastAPI runs sync routes in a thread pool
        self._by_owner: dict[str, dict[UUID, Todo]] = {}

    def list(self, owner: str) -> list[Todo]:
        with self._lock:
            return list(self._by_owner.get(owner, {}).values())

    def get(self, owner: str, todo_id: UUID) -> Optional[Todo]:
        with self._lock:
            return self._by_owner.get(owner, {}).get(todo_id)

    def create(self, owner: str, data: TodoCreate) -> Todo:
        todo = Todo(id=uuid4(), title=data.title, done=data.done, created_at=datetime.now(timezone.utc))
        with self._lock:
            self._by_owner.setdefault(owner, {})[todo.id] = todo
        return todo

    def update(self, owner: str, todo_id: UUID, data: TodoUpdate) -> Optional[Todo]:
        with self._lock:
            todo = self._by_owner.get(owner, {}).get(todo_id)
            if todo is None:
                return None
            updated = todo.model_copy(update=data.model_dump(exclude_none=True))
            self._by_owner[owner][todo_id] = updated
            return updated

    def delete(self, owner: str, todo_id: UUID) -> bool:
        with self._lock:
            return self._by_owner.get(owner, {}).pop(todo_id, None) is not None
