from datetime import datetime, timedelta, timezone


def build_security_posture(scan_stats: dict, report_stats: dict) -> dict:
    total_scans = scan_stats.get("total_scans", 0)
    danger_scans = scan_stats.get("danger_scans", 0)
    warn_scans = scan_stats.get("warn_scans", 0)
    average_score = scan_stats.get("average_score", 0)
    total_reports = report_stats.get("total_reports", 0)

    pressure_score = min(
        100,
        round(
            (danger_scans * 12)
            + (warn_scans * 5)
            + (average_score * 0.5)
            + (total_reports * 4)
        ),
    )

    alerts = []
    if danger_scans >= 3:
        alerts.append(
            {
                "level": "danger",
                "title": "Rafale de liens dangereux",
                "detail": f"{danger_scans} scans dangereux detectes sur la fenetre active.",
            }
        )
    if average_score >= 55:
        alerts.append(
            {
                "level": "warn",
                "title": "Risque moyen eleve",
                "detail": f"Le score moyen de risque atteint {average_score}/100.",
            }
        )
    if _recent_count(scan_stats.get("trend_last_7_days", []), 2) >= 8:
        alerts.append(
            {
                "level": "warn",
                "title": "Pic recent d'activite",
                "detail": "Le volume de scans sur les deux derniers jours est anormalement eleve.",
            }
        )
    if total_reports >= 4:
        dominant_type = _dominant_report_type(report_stats.get("by_type", {}))
        alerts.append(
            {
                "level": "danger" if dominant_type == "phishing" else "warn",
                "title": "Signalements communautaires en hausse",
                "detail": f"{total_reports} signalements recents observes. Type dominant: {dominant_type}.",
            }
        )

    return {
        "pressure_score": pressure_score,
        "alerts": alerts,
        "posture": _resolve_posture(pressure_score, total_scans),
    }


def _resolve_posture(pressure_score: int, total_scans: int) -> str:
    if total_scans == 0:
        return "idle"
    if pressure_score >= 75:
        return "critical"
    if pressure_score >= 40:
        return "elevated"
    return "stable"


def _recent_count(window: list[dict], days: int) -> int:
    if not window:
        return 0
    today = datetime.now(timezone.utc).date()
    accepted = {(today - timedelta(days=offset)).isoformat() for offset in range(days)}
    return sum(item.get("count", 0) for item in window if item.get("day") in accepted)


def _dominant_report_type(by_type: dict[str, int]) -> str:
    if not by_type:
        return "aucun"
    return max(by_type.items(), key=lambda item: item[1])[0]
