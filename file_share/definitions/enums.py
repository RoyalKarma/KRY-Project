from enum import Enum


class SendStatus(Enum):
    SUCCESS = 0
    UNKNOWN_USER = 1
    NOT_FRIEND = 2
    REFUSED_QUEUED = 3
    QUEUED = 4
