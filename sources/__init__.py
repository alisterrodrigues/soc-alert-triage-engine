"""Alert source provider package.

fetch() return contract: FileSource returns a list of Alert dataclass instances
(already normalized). SplunkSource and ElasticSource return lists of raw field
dicts that must be normalized via ingestion._validate_and_build() before use.
Callers must handle both variants based on the source type.
"""
from sources.base import AlertSource
from sources.file_source import FileSource

__all__ = ["AlertSource", "FileSource"]
