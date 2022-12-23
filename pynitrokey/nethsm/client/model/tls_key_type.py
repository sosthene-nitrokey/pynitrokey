# coding: utf-8

"""
    NetHSM

    All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All <a href=\"https://tools.ietf.org/html/rfc4648#section-4\">base64</a> encoded values are Big Endian.  # noqa: E501

    The version of the OpenAPI document: v1
    Generated by: https://openapi-generator.tech
"""

from datetime import date, datetime  # noqa: F401
import decimal  # noqa: F401
import functools  # noqa: F401
import io  # noqa: F401
import re  # noqa: F401
import typing  # noqa: F401
import typing_extensions  # noqa: F401
import uuid  # noqa: F401

import frozendict  # noqa: F401

from pynitrokey.nethsm.client import schemas  # noqa: F401


class TlsKeyType(
    schemas.EnumBase,
    schemas.StrSchema
):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """


    class MetaOapg:
        enum_value_to_name = {
            "RSA": "RSA",
            "Curve25519": "CURVE25519",
            "EC_P224": "EC_P224",
            "EC_P256": "EC_P256",
            "EC_P384": "EC_P384",
            "EC_P521": "EC_P521",
        }
    
    @schemas.classproperty
    def RSA(cls):
        return cls("RSA")
    
    @schemas.classproperty
    def CURVE25519(cls):
        return cls("Curve25519")
    
    @schemas.classproperty
    def EC_P224(cls):
        return cls("EC_P224")
    
    @schemas.classproperty
    def EC_P256(cls):
        return cls("EC_P256")
    
    @schemas.classproperty
    def EC_P384(cls):
        return cls("EC_P384")
    
    @schemas.classproperty
    def EC_P521(cls):
        return cls("EC_P521")
