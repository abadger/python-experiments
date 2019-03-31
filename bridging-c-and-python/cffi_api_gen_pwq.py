# coding: utf-8
# cffi libpwquality bindings for pip installation
# Copyright: 2019, Toshio Kuratomi <toshio@fedoraproject.org>
# License: BSD or GPLv2+ at your option

"""
This package contains bindings to the libpwquality python module using cffi.  Although pwquality
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

import sys

import cffi


#
# Helper functions
#

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


#
# This code builds the extension.  It is done at runtime here but it could be used
# When building and installing the package instead.  It generates a .c file and compiles it.
#

def build_extension():
    ffibuilder = cffi.FFI()

    #'/srv/git/libpwquality/libpwquality/src/pwqprivate.h'

    ffibuilder.set_source("built_cffi_api_pwq", '#include "pwquality.h"', libraries=['pwquality'])

    with open('pwquality.h', 'r') as f:
        defines = []
        in_comment = False
        extern_flag = False
        for line in f:
            test_line = line.strip()
            if test_line.startswith('#if') or test_line.startswith('#endif'):
                continue
            elif test_line.startswith('/*'):
                if test_line.endswith('*/'):
                    continue
                in_comment = True
                continue
            elif in_comment and test_line.endswith('*/'):
                in_comment = False
                continue
            elif test_line.startswith('extern "C" {'):
                extern_flag = True
                continue
            elif test_line.startswith('#define'):
                if len(test_line.split()) <= 2:
                    continue

            if in_comment:
                continue
            defines.append(line)

        if extern_flag:
            for idx, line in reversed(list(enumerate(defines))):
                if line.startswith('}'):
                    break
            del defines[idx]
        defines = '\n'.join(defines)

    ffibuilder.cdef(defines)

    ffibuilder.compile(verbose=True)

#
# Pythonic-API layer
#

# Load the bindings or generate and compile the bindings and then load them
try:
    import built_cffi_api_pwq as _LIBPWQ
except Exception:
    build_extension()
    import built_cffi_api_pwq as _LIBPWQ


# Import the constants into the namespace here.  The upstream extension module makes the constants
# available to calling python code so that's why we do this here.
def import_constants():
    global_vars = globals()
    attributes = dir(_LIBPWQ.lib)
    for attrib in attributes:
        if attrib.startswith('PWQ_'):
            global_vars[attrib] = getattr(_LIBPWQ.lib, attrib)


import_constants()


#
# The main portion of the bindings
#

class PWQError(Exception):
    """
    Standard exception thrown from PWQSettings method calls

    The exception value is always an integer error code and string description.
    """
    @staticmethod
    def from_pwq_rc(rc, auxerror=None):
        if rc == PWQ_ERROR_MEM_ALLOC:
            return MemoryError()

        buf = _LIBPWQ.ffi.new('char []', b'\0' * (PWQ_MAX_ERROR_MESSAGE_LEN - 1))
        msg = _LIBPWQ.lib.pwquality_strerror(buf, len(buf), rc, auxerror)
        print(auxerror)
        return PWQError(rc, to_native(_LIBPWQ.ffi.string(msg)))

    def __repr__(self):
        return 'PWQError(%r, %r)' % (self.args[0], self.args[1])

    def __str__(self):
        return '(%r, %r)' % (self.args[0], self.args[1])


class PWQSettings:
    def __init__(self):
        self._pwqsettings = _LIBPWQ.lib.pwquality_default_settings()
        if self._pwqsettings is None:
            raise MemoryError

    def __del__(self):
        _LIBPWQ.lib.pwquality_free_settings(self._pwqsettings)

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
        pass

    def generate(self, entropy):
        """
        Generate password with requested entropy

        :arg entropy: integer entropy bits used to generate the password
        """
        password_ptr = _LIBPWQ.ffi.new('char **', None)

        rc = _LIBPWQ.lib.pwquality_generate(self._pwqsettings, entropy, password_ptr)
        if rc < 0:
            raise PWQError.from_pwq_rc(rc)
        return to_native(_LIBPWQ.ffi.string(password_ptr[0]))

    def check(self, password, oldpassword=None, username=None):
        """
        Check whether the password conforms to the requirements and return password strength score

        :arg password: password string to be checked
        :kwarg oldpassword: old password string (or None) for additional checks
        :kwarg username: user name (or None) for additional checks
        """
        auxerror_ptr = _LIBPWQ.ffi.new('void **', None)

        password = to_bytes(password)
        oldpassword = to_bytes(oldpassword) or _LIBPWQ.ffi.NULL
        username = to_bytes(username) or _LIBPWQ.ffi.NULL

        rc = _LIBPWQ.lib.pwquality_check(self._pwqsettings, password, oldpassword,
                                         username, auxerror_ptr)
        if rc < 0:
            raise PWQError.from_pwq_rc(rc, auxerror_ptr[0])

        return rc
