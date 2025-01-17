/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/**
 * @bug 8217375
 * @summary This test runs those test cases of {@link Compatibility} test nearby
 * which can be executed within the currently built and tested JDK and without
 * TSA, with only one digest algorithm and with only one key (algorithm and
 * size) and without delayed verification.
 * Other test cases are to be executed manually invoking {@link Compatibility}
 * involving more than the currently built and tested JDK verifying the
 * compatibility of jarsigner across different JDK releases.
 * For more details about the test and its usages, please look at the README.
 */
/*
 * @test
 * @library /test/lib ../warnings
 * @compile Compatibility.java
 * @run main/othervm
 *  -Djava.security.properties=./java.security
 *  -Duser.language=en
 *  -Duser.country=US
 *  -DjdkList=TEST_JDK
 *  -DtsaList=notsa
 *  -Dexpired=false
 *  -DtestComprehensiveJarContents=true
 *  -DtestJarUpdate=true
 *  -Dstrict=true
 *  -DkeyAlgs=EC;#RSA;#DSA;
 *  -DdigestAlgs=SHA-512
 *  SignTwice
 */
public class SignTwice {

    public static void main(String[] args) throws Throwable {
        Compatibility.main(args);
    }

}
