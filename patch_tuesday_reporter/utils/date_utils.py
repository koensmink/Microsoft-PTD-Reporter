# patch_tuesday_reporter/utils/date_utils.py
from datetime import datetime, timedelta
from dateutil import tz

def now_in_tz(tzname: str) -> datetime:
    """Geef de huidige tijd terug in de opgegeven timezone."""
    return datetime.now(tz.gettz(tzname))

def is_second_tuesday(dt: datetime) -> bool:
    """Check of de datum de tweede dinsdag van de maand is."""
    first = dt.replace(day=1)
    first_weekday = first.weekday()  # Monday=0 ... Sunday=6
    days_to_tue = (1 - first_weekday) % 7
    first_tuesday = first + timedelta(days=days_to_tue)
    second_tuesday = first_tuesday + timedelta(days=7)
    return dt.date() == second_tuesday.date()

def yyyymm(dt: datetime) -> str:
    return dt.strftime("%Y-%m")

def yyyymmdd(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")
