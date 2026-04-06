from .health import router as health_router
from .reports import router as reports_router
from .scan import router as scan_router
from .stats import router as stats_router

__all__ = ["health_router", "reports_router", "scan_router", "stats_router"]
