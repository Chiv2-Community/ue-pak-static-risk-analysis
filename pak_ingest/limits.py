"""Trusted deployment settings; never supplied by an archive."""

from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 256 * 1024 * 1024
    index_bytes: int = 16 * 1024 * 1024
    entries: int = 10000
    string_bytes: int = 1024
    blocks: int = 65536
    member_bytes: int = 128 * 1024 * 1024
    total_output_bytes: int = 512 * 1024 * 1024
    expansion_ratio: int = 200
    scratch_bytes: int = 800 * 1024 * 1024
    report_bytes: int = 16 * 1024 * 1024
    wall_seconds: int = 30
    cpu_seconds: int = 20
    address_space_bytes: int = 512 * 1024 * 1024
    file_bytes: int = 512 * 1024 * 1024
    open_files: int = 32

    def validate(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError("invalid_limits")
        if self.open_files < 16:
            raise ValueError("invalid_limits")
        return self

    def as_dict(self):
        return asdict(self)


class Rejected(Exception):
    """Only fixed diagnostic codes may cross the worker boundary."""


def require(condition, code):
    if not condition:
        raise Rejected(code)
