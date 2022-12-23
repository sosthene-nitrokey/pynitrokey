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


class DecryptMode(
    schemas.EnumBase,
    schemas.StrSchema
):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """


    class MetaOapg:
        enum_value_to_name = {
            "RAW": "RAW",
            "PKCS1": "PKCS1",
            "OAEP_MD5": "OAEP_MD5",
            "OAEP_SHA1": "OAEP_SHA1",
            "OAEP_SHA224": "OAEP_SHA224",
            "OAEP_SHA256": "OAEP_SHA256",
            "OAEP_SHA384": "OAEP_SHA384",
            "OAEP_SHA512": "OAEP_SHA512",
            "AES_CBC": "AES_CBC",
        }
    
    @schemas.classproperty
    def RAW(cls):
        return cls("RAW")
    
    @schemas.classproperty
    def PKCS1(cls):
        return cls("PKCS1")
    
    @schemas.classproperty
    def OAEP_MD5(cls):
        return cls("OAEP_MD5")
    
    @schemas.classproperty
    def OAEP_SHA1(cls):
        return cls("OAEP_SHA1")
    
    @schemas.classproperty
    def OAEP_SHA224(cls):
        return cls("OAEP_SHA224")
    
    @schemas.classproperty
    def OAEP_SHA256(cls):
        return cls("OAEP_SHA256")
    
    @schemas.classproperty
    def OAEP_SHA384(cls):
        return cls("OAEP_SHA384")
    
    @schemas.classproperty
    def OAEP_SHA512(cls):
        return cls("OAEP_SHA512")
    
    @schemas.classproperty
    def AES_CBC(cls):
        return cls("AES_CBC")
