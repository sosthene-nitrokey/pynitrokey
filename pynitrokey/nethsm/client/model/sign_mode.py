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


class SignMode(
    schemas.EnumBase,
    schemas.StrSchema
):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """


    class MetaOapg:
        enum_value_to_name = {
            "PKCS1": "PKCS1",
            "PSS_MD5": "PSS_MD5",
            "PSS_SHA1": "PSS_SHA1",
            "PSS_SHA224": "PSS_SHA224",
            "PSS_SHA256": "PSS_SHA256",
            "PSS_SHA384": "PSS_SHA384",
            "PSS_SHA512": "PSS_SHA512",
            "EdDSA": "ED_DSA",
            "ECDSA": "ECDSA",
        }
    
    @schemas.classproperty
    def PKCS1(cls):
        return cls("PKCS1")
    
    @schemas.classproperty
    def PSS_MD5(cls):
        return cls("PSS_MD5")
    
    @schemas.classproperty
    def PSS_SHA1(cls):
        return cls("PSS_SHA1")
    
    @schemas.classproperty
    def PSS_SHA224(cls):
        return cls("PSS_SHA224")
    
    @schemas.classproperty
    def PSS_SHA256(cls):
        return cls("PSS_SHA256")
    
    @schemas.classproperty
    def PSS_SHA384(cls):
        return cls("PSS_SHA384")
    
    @schemas.classproperty
    def PSS_SHA512(cls):
        return cls("PSS_SHA512")
    
    @schemas.classproperty
    def ED_DSA(cls):
        return cls("EdDSA")
    
    @schemas.classproperty
    def ECDSA(cls):
        return cls("ECDSA")
