from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.timeutils import utcnow


class AnomalyResult(Base):
    __tablename__ = "anomaly_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    score: Mapped[float] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict] = mapped_column(JSON)
    explanation: Mapped[dict] = mapped_column(JSON)
    model_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    host: Mapped["Host"] = relationship()  # noqa: F821

    @property
    def host_ip(self) -> str:
        return self.host.ip
