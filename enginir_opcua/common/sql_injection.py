"""Quoting of SQL identifiers built from data."""


def quote_identifier(name: str) -> str:
    """Quote an SQL identifier, so that any character in it, including a double quote, stays part of the name."""
    return '"' + name.replace('"', '""') + '"'
