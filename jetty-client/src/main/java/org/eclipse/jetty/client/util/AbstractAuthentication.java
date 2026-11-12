//
//  ========================================================================
//  Copyright (c) 1995-2022 Mort Bay Consulting Pty Ltd and others.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.client.util;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.Authentication;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.URIUtil;

public abstract class AbstractAuthentication implements Authentication
{
    // ASCII characters, other than letters and digits, that are safe to decode when canonicalizing URI paths.
    private static final String SAFE_CHARACTERS = "!$&'()*+,-.:=@_~";

    private final URI uri;
    private final String realm;

    public AbstractAuthentication(URI uri, String realm)
    {
        this.uri = uri;
        this.realm = realm;
    }

    public abstract String getType();

    public URI getURI()
    {
        return uri;
    }

    public String getRealm()
    {
        return realm;
    }

    @Override
    public boolean matches(String type, URI uri, String realm)
    {
        if (!getType().equalsIgnoreCase(type))
            return false;

        if (!this.realm.equals(ANY_REALM) && !this.realm.equals(realm))
            return false;

        return matchesURI(this.uri, uri);
    }

    public static boolean matchesURI(URI uri1, URI uri2)
    {
        String scheme = uri1.getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase(uri2.getScheme()))
            return false;

        String host = uri1.getHost();
        if (host == null || !host.equalsIgnoreCase(uri2.getHost()))
            return false;

        // Handle default HTTP ports.
        if (HttpClient.normalizePort(scheme, uri1.getPort()) != HttpClient.normalizePort(scheme, uri2.getPort()))
            return false;

        // Compare canonical paths.
        String path1 = canonicalPath(uri1.getRawPath());
        String path2 = canonicalPath(uri2.getRawPath());
        if (path1 == null || path2 == null)
            return false;

        if (path1.endsWith("/"))
            path1 = path1.substring(0, path1.length() - 1);

        if (path1.isEmpty())
            return true;

        if (!path2.startsWith(path1))
            return false;

        if (path2.length() == path1.length())
            return true;

        // Must match at a segment boundary.
        return path2.charAt(path1.length()) == '/';
    }

    /**
     * <p>Converts the given raw (percent-encoded) URI path to a canonical form suitable for URI matching.</p>
     * <p>Path parameters are removed; percent-encoded characters that are safe to decode are decoded,
     * while unsafe characters (such as {@code /}, {@code %}, {@code ;}, {@code ?} and non-ASCII characters)
     * are kept, or made, percent-encoded with uppercase hex digits; finally, {@code .} and {@code ..}
     * segments are resolved.</p>
     *
     * @param rawPath the raw URI path
     * @return the canonical path, or null if the path is null, has an invalid percent-encoding,
     * or tries to navigate above its root
     */
    private static String canonicalPath(String rawPath)
    {
        if (rawPath == null)
            return null;

        int length = rawPath.length();
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; ++i)
        {
            char c = rawPath.charAt(i);
            if (c == '%')
            {
                if (i + 2 >= length)
                    return null;
                int hi = Character.digit(rawPath.charAt(i + 1), 16);
                int lo = Character.digit(rawPath.charAt(i + 2), 16);
                if (hi < 0 || lo < 0)
                    return null;
                appendCanonical(builder, hi * 16 + lo);
                i += 2;
            }
            else if (c == ';')
            {
                // Remove the path parameters, up to the next segment.
                while (++i < length)
                {
                    if (rawPath.charAt(i) == '/')
                    {
                        builder.append('/');
                        break;
                    }
                }
            }
            else if (c == '/')
            {
                builder.append(c);
            }
            else if (c < 0x80)
            {
                appendCanonical(builder, c);
            }
            else
            {
                // Percent-encode the UTF-8 bytes of a run of non-ASCII characters.
                int start = i;
                while (i + 1 < length && rawPath.charAt(i + 1) >= 0x80)
                {
                    ++i;
                }
                byte[] bytes = rawPath.substring(start, i + 1).getBytes(StandardCharsets.UTF_8);
                for (byte b : bytes)
                {
                    appendCanonical(builder, b & 0xFF);
                }
            }
        }

        // Resolve dot segments; null is returned if the path navigates above its root.
        return URIUtil.canonicalPath(builder.toString());
    }

    private static void appendCanonical(StringBuilder builder, int code)
    {
        if (isSafe(code))
        {
            builder.append((char)code);
        }
        else
        {
            builder.append('%');
            TypeUtil.toHex((byte)code, builder);
        }
    }

    private static boolean isSafe(int code)
    {
        if ((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') || (code >= '0' && code <= '9'))
            return true;
        return SAFE_CHARACTERS.indexOf(code) >= 0;
    }
}
