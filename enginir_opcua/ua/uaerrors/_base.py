"""
Define exceptions to be raised at various places in the stack
"""

from typing import Any, ClassVar


class UaError(RuntimeError):
    pass


class SignatureError(UaError):
    pass


class ConfigurationError(UaError):
    pass


class DecryptionError(UaError):
    pass


class _StatusCodeAttribute:
    def __get__(self, instance: "UaStatusCodeError | None", owner: type["UaStatusCodeError"]) -> Any:
        if instance is None:
            return owner._class_code
        return instance.args[0]


class UaStatusCodeError(UaError):
    """
    This exception is raised when a bad status code is encountered.

    It exposes the status code number in the `code` property, so the
    user can distinguish between the different status codes and maybe
    handle some of them.

    The list of status error codes can be found in enginir_opcua.ua.status_codes.
    """

    _subclasses: ClassVar[dict[int, type["UaStatusCodeError"]]] = {}
    _class_code: ClassVar[int | None] = None

    def __init_subclass__(cls) -> None:
        class_code = cls.__dict__.get("code")
        if isinstance(class_code, int):
            cls._class_code = class_code
            del cls.code
            cls._subclasses[class_code & 0xFFFF0000] = cls

    def __new__(cls, *args: Any) -> "UaStatusCodeError":
        """
        Creates a new UaStatusCodeError but returns a more specific subclass
        if possible, e.g.

            UaStatusCodeError(0x80010000) => BadUnexpectedError()

        The lookup ignores the low 16 bits, which are flags (OPC 10000-4 v1.05, 7.38.1).
        """

        if args:
            code, *args = args
            if isinstance(code, int):
                cls = cls._subclasses.get(code & 0xFFFF0000, cls)

        return UaError.__new__(cls, *args)

    def __init__(self, code: int | str | None = None, detail: str | None = None) -> None:
        """
        :param code: The code of the exception. Only needed when not instanciating
                     a concrete subclass such as BadInternalError.
        :param detail: Optional text that says why the status was raised.
        """
        if code is None:
            if type(self)._class_code is None:
                raise TypeError("UaStatusCodeError(code) cannot be instantiated without a status code.")
            code = type(self)._class_code
        UaError.__init__(self, code)
        self.detail = detail

    def __str__(self) -> str:
        import enginir_opcua.ua.status_codes as status_codes

        code = self.code
        if not isinstance(code, int):
            return str(code)
        text = "{1}({0})".format(*status_codes.get_name_and_doc(code & 0xFFFF0000))
        return f"{text}: {self.detail}" if self.detail else text

    code = _StatusCodeAttribute()


class UaStatusCodeErrors(UaStatusCodeError):
    def __new__(cls, *args: Any) -> "UaStatusCodeErrors":
        # use the default implementation
        self = UaError.__new__(cls, *args)
        return self

    def __init__(self, codes: list[int]) -> None:
        """
        :param codes: The codes of the results.
        """
        UaError.__init__(self, codes)
        self.codes = codes

    def __str__(self) -> str:
        import enginir_opcua.ua.status_codes as status_codes

        return "[{0}]".format(
            ", ".join(["{1}({0})".format(*status_codes.get_name_and_doc(code & 0xFFFF0000)) for code in self.codes])
        )

    @property
    def code(self) -> int | None:
        """
        The first code with a severity other than Good, or None.
        """
        from enginir_opcua.ua.uatypes import StatusCode

        error_codes = [code for code in self.codes if not StatusCode(code).is_good()]
        return error_codes[0] if len(error_codes) > 0 else None


class UaStringParsingError(UaError):
    pass


class UaStructParsingError(UaError):
    pass


class UaInvalidParameterError(UaError):
    pass
