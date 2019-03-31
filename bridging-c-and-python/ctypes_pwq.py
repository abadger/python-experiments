# coding: utf-8
# ctype libpwquality bindings for pip installation
# Copyright: 2019, Toshio Kuratomi <toshio@fedoraproject.org>
# License: BSD or GPLv2+ at your option

"""
This package contains bindings to the libpwquality python module using ctypes.  Although pwquality
itself ships with bindings, the distribution you are on may not ship with those binds build for the
particular Python interpreter which you are using.  Without some form of bindings hosted on pypi,
you would then be forced to download the libpwquality distribution and build everything from there.

This package attempts to ease that burden with a pure Python implementation of bindings that you can
run anywhere.  The implementation here closely mirrors the official python libpwquality API so that
it is easy for you to switch.
"""
# Make code behave more similarly on Python2 and Python3
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import ctypes as ct
import sys


PY3 = False
if sys.version_info >= (3,):
    PY3 = True
    unicode = str


def to_bytes(obj, encoding='utf-8', errors='strict'):
    if isinstance(obj, unicode):
        return obj.encode(encoding, errors)
    return obj


def to_text(obj, encoding='utf-8', errors='strict'):
    if isinstance(obj, bytes):
        return obj.decode(encoding, errors)
    return obj


if PY3:
    to_native = to_text
else:
    to_native = to_bytes


def retrieve_constants(header_file):
    constants = {}
    with open(header_file, 'r') as hf:
        for line in hf:
            if line.startswith('#define PWQ_'):
                s = line.split()
                constants[s[1]] = int(s[2])
    return constants


def build_constants(header_file, output_file):
    """
    Initialization that loads the constants that the libpwquality bindings have

    This is the same algorithm as pwquality uses during its build
    """
    constants = retrieve_constants(header_file)
    with open(output_file, 'w') as of:
        of.write('# This file is generated at build time from pwquality.h\n')
        for name, value in constants.items():
            of.write('%s = %s\n' % (name, value))


def init_constants():
    header_file = 'pwquality.h'
    constants = retrieve_constants(header_file)
    global_vars = globals()
    for name, value in constants.items():
        global_vars[name] = value


LP_c_char = ct.POINTER(ct.c_char)  # Real char * [when we need char ** in a function)


def init_libpwquality():
    libpwq = ct.CDLL('libpwquality.so.1')
    libpwq.pwquality_default_settings.restype = ct.c_void_p

    libpwq.pwquality_strerror.argtypes = (ct.c_char_p, ct.c_int, ct.c_int, ct.c_void_p)
    libpwq.pwquality_strerror.restype = ct.c_char_p

    libpwq.pwquality_free_settings.argtypes = (ct.c_void_p,)

    libpwq.pwquality_generate.argtypes = (ct.c_void_p, ct.c_int, ct.POINTER(LP_c_char))
    libpwq.pwquality_generate.restype = ct.c_int

    libpwq.pwquality_check.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_char_p, ct.c_char_p,
                                       ct.c_void_p)
    libpwq.pwquality_check.restype = ct.c_int

    return libpwq


try:
    from .constants import *
except Exception:
    init_constants()

_LIBPWQ = init_libpwquality()


class PWQError(Exception):
    """
    Standard exception thrown from PWQSettings method calls

    The exception value is always an integer error code and string description.
    """
    @staticmethod
    def from_pwq_rc(rc, auxerror=None):
        if rc == PWQ_ERROR_MEM_ALLOC:
            return MemoryError()

        buf = ct.create_string_buffer(b'\000' * PWQ_MAX_ERROR_MESSAGE_LEN)
        msg = _LIBPWQ.pwquality_strerror(buf, len(buf), rc, auxerror)
        return PWQError(rc, to_native(msg))

    def __repr__(self):
        return 'PWQError(%r, %r)' % (self.args[0], self.args[1])

    def __str__(self):
        return '(%r, %r)' % (self.args[0], self.args[1])


class PWQSettings(object):
    """PWQSettings objects - libpwquality functionality wrapper"""

    def __init__(self):

        self._pwqsettings = _LIBPWQ.pwquality_default_settings()
        if self._pwqsettings is None:
            raise MemoryError

    def __del__(self):
        _LIBPWQ.pwquality_free_settings(self._pwqsettings)

    def read_config(self, cfgfilename=None):
        """
        Read the settings from configuration file

        :kwarg cfgfilename: path to the configuration file (optional)
        """
        pass

    def set_option(self, option):
        """
        Set option from name=value pair

        :arg option: string with the name=value pair
        """
        if rc in (PWQ_ERROR_UNKNOWN_SETTING, PWQ_ERROR_NON_INT_SETTING,
                        PWQ_ERROR_NON_STR_SETTING):
            raise AttributeError(rc, to_native(msg.value))
        pass

    def generate(self, entropy):
        """
        Generate password with requested entropy

        :arg entropy: integer entropy bits used to generate the password
        """
        password = ct.create_string_buffer(b'\000' * 100)
        password_ptr = LP_c_char(password)

        rc = _LIBPWQ.pwquality_generate(self._pwqsettings, entropy, ct.byref(password_ptr))
        if rc < 0:
            raise PWQError.from_pwq_rc(rc)
        p = ct.cast(password_ptr, ct.c_char_p)
        return to_native(p.value)

    def check(self, password, oldpassword=None, username=None):
        """
        Check whether the password conforms to the requirements and return password strength score

        :arg password: password string to be checked
        :kwarg oldpassword: old password string (or None) for additional checks
        :kwarg username: user name (or None) for additional checks
        """
        c_password = ct.create_string_buffer(to_bytes(password))

        if oldpassword:
            c_oldpassword = ct.create_string_buffer(to_bytes(oldpassword))
        else:
            c_oldpassword = oldpassword

        if username:
            c_username = ct.create_string_buffer(to_bytes(username))
        else:
            c_username = username

        auxerror = ct.c_void_p()

        rc = _LIBPWQ.pwquality_check(self._pwqsettings, c_password, c_oldpassword,
                                          c_username, ct.byref(auxerror))
        if rc < 0:
            raise PWQError.from_pwq_rc(rc, auxerror)

        return rc
