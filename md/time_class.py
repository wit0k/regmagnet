from datetime import datetime, timedelta, date
from dateutil import parser
        
def _int(input_data, default=1):
    try:
        return round(int(input_data))
    except Exception as msg:
        return default

def now():
    return datetime.now()

def hours_ago(input_data):
    _count = _int(input_data)
    return datetime.now() - timedelta(hours=_count)

def days_ago(input_data=7):
    _count = _int(input_data)
    return datetime.now() - timedelta(days=_count)

def weeks_ago(input_data):
    _count = _int(input_data)
    return datetime.now() - timedelta(weeks=_count)

def week_start():
    today = datetime.now().date()
    start = today - timedelta(days=today.weekday())
    start = datetime.combine(start, datetime.min.time())
    return start # I could make + timedelta(microseconds=1) to display miliseconds, but it is not necessary

def week_end():
    today = datetime.now().date()
    start = today - timedelta(days=today.weekday())
    start = datetime.combine(start, datetime.min.time())
    start = start - timedelta(milliseconds=1)
    return start + timedelta(days=6)

def last_week_start():
    today = datetime.now().date() - timedelta(days=7)
    start = today - timedelta(days=today.weekday())
    start = datetime.combine(start, datetime.min.time())
    return start

def last_week_end():
    today = datetime.now().date() - timedelta(days=7)
    start = today - timedelta(days=today.weekday())
    start = datetime.combine(start, datetime.min.time())
    return start + timedelta(days=7) - timedelta(milliseconds=1)

def current_year_start():
    _date = date(date.today().year, 1, 1)
    return datetime.combine(_date, datetime.min.time())

def current_year_end():
    _date = date(date.today().year, 12, 31)
    return datetime.combine(_date, datetime.min.time())

def today():
    return datetime.now().date()

def today_day_start():
    return datetime.utcnow().date()

def dt_to_str(_dt, strftime='%Y-%m-%d %H:%M:%S.%f'):

    if isinstance(_dt, datetime):
        return _dt.strftime(strftime)

def str_to_dt(strtime):
    # strtime = '2009-03-08T00:27:31.807Z'
    return parser.parse(strtime) # .timestamp()