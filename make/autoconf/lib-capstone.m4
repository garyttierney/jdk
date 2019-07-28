#
# Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.  Oracle designates this
# particular file as subject to the "Classpath" exception as provided
# by Oracle in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
# or visit www.oracle.com if you need additional information or have any
# questions.
#

################################################################################
# Setup Capstone (disassembler)
################################################################################
AC_DEFUN_ONCE([LIB_SETUP_CAPSTONE],
[
  AC_ARG_WITH(capstone, [AS_HELP_STRING([--with-capstone],
      [specify directory with the capstone library])])

  if test "x$with_capstone" != "x"; then
    CAPSTONE_ENABLED="true"
    CAPSTONE_LIB_FILE=[$LIBRARY_PREFIX]["capstone"][$SHARED_LIBRARY_SUFFIX]

    # User specified a base dir for the Capstone library
    if test "x${with_capstone}" != xyes; then
      CAPSTONE_LIB_DIR="$with_capstone"
      CAPSTONE_INCLUDE_DIR="$with_capstone"/include
    else
      CAPSTONE_INCLUDE_DIR="/usr/include/capstone"
      CAPSTONE_LIB_DIR="/usr/lib64"
    fi

    BASIC_FIXUP_PATH(CAPSTONE_LIB_DIR)
    BASIC_FIXUP_PATH(CAPSTONE_INCLUDE_DIR)

    if test "x$TOOLCHAIN_TYPE" = "xmicrosoft"; then
      CAPSTONE_LIBS="capstone.lib"
      CAPSTONE_CXXFLAGS="/I $CAPSTONE_INCLUDE_DIR"
      CAPSTONE_LD_FLAGS="/LIBPATH:$CAPSTONE_LIB_DIR"
    else
      CAPSTONE_LIBS="-lcapstone"
      CAPSTONE_CXXFLAGS="-I$CAPSTONE_INCLUDE_DIR"
      CAPSTONE_LD_FLAGS="-L$CAPSTONE_LIB_DIR"
    fi

    # TODO determine following constants based on OPENJDK_BUILD_CPU,
    # OPENJDK_BUILD_CPU_ARCH, OPENJDK_BUILD_CPU_BITS, OPENJDK_BUILD_CPU_ENDIAN

    # Constant of cs_arch enum
    CAPSTONE_CXXFLAGS+=" -DARCH=CS_ARCH_X86"
    # Constant of cs_mode enum
    CAPSTONE_CXXFLAGS+=" -DMODE=CS_MODE_64"

    AC_MSG_NOTICE([CAPSTONE_LIB_DIR: $CAPSTONE_LIB_DIR])
    AC_MSG_NOTICE([CAPSTONE_LIB_FILE: $CAPSTONE_LIB_FILE])
    AC_MSG_NOTICE([CAPSTONE_LIBS: $CAPSTONE_LIBS])
    AC_MSG_NOTICE([CAPSTONE_CXXFLAGS: $CAPSTONE_CXXFLAGS])
    AC_MSG_NOTICE([CAPSTONE_LD_FLAGS: $CAPSTONE_LD_FLAGS])

    # TODO actual checking that the library is valid
  else
    CAPSTONE_ENABLED="false"
  fi

  AC_SUBST(CAPSTONE_ENABLED)
  AC_SUBST(CAPSTONE_LIB_DIR)
  AC_SUBST(CAPSTONE_LIB_FILE)
  AC_SUBST(CAPSTONE_LIBS)
  AC_SUBST(CAPSTONE_CXXFLAGS)
  AC_SUBST(CAPSTONE_LD_FLAGS)
])