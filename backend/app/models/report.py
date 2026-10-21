from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.timeutils import utcnow


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    generated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[bytes] = mapped_column(LargeBinary)
