from contextvars import ContextVar

filter_suspicious = ContextVar("filter_suspicious", default=True)
