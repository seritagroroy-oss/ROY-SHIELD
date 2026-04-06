from .health import router as health_router
from .scan import router as scan_router
from .stats import router as stats_router

__all__ = ["health_router", "scan_router", "stats_router"]
