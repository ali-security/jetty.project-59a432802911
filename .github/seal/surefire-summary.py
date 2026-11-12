#!/usr/bin/env python3
"""Print a per-module Surefire summary and a reason for every skipped test.

Reads every target/surefire-reports/TEST-*.xml below the given root. Surefire
3.x leaves the <skipped> message empty for JUnit 5 assumption aborts and some
disabled conditions, so for those the reason is recovered from the test source:
the @Disabled*/@Enabled*/@Tag annotation on the method or class, or the
assume*/Assumptions call inside the method (following private helpers).
"""
import collections
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

ANNOT_RE = re.compile(r"@(Disabled\w*|Enabled\w*|Tag)\b.*")
ASSUME_RE = re.compile(r"\b(assume\w*|Assumptions\.\w+|Assume\.\w+)\s*\(")


def source_for(module_dir, classname):
    outer = classname.split("$")[0]
    path = os.path.join(module_dir, "src", "test", "java", *outer.split(".")) + ".java"
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    return None


def method_bounds(lines, method):
    decl = re.compile(r"^\s*(public|protected|private|static|void|final|\w+<).*\b" + re.escape(method) + r"\s*\(")
    for i, line in enumerate(lines):
        if decl.search(line) and not line.strip().startswith("//"):
            depth, started = 0, False
            for j in range(i, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and depth <= 0:
                    return i, j
            return i, len(lines) - 1
    return None


def annotations_before(lines, idx):
    found = []
    k = idx - 1
    while k >= 0:
        s = lines[k].strip()
        if s.startswith("@") or s.startswith("//") or s.startswith("*") or s.startswith("/*") or s == "" or s.endswith(",") or s.startswith('"') or s.startswith(")"):
            m = ANNOT_RE.search(s)
            if m:
                found.append(m.group(0))
            if s == "" and k < idx - 1 and not lines[k + 1].strip().startswith("@"):
                break
            k -= 1
            continue
        break
    return found


def assumes_in(lines, bounds, depth=0, seen=None):
    seen = seen or set()
    out = []
    start, end = bounds
    for n in range(start, end + 1):
        s = lines[n].strip()
        if ASSUME_RE.search(s):
            comment = ""
            if n > 0 and lines[n - 1].strip().startswith("//"):
                comment = " (" + lines[n - 1].strip().lstrip("/ ") + ")"
            out.append(s + comment)
    if not out and depth < 2:
        for n in range(start + 1, end + 1):
            for call in re.findall(r"\b([a-z]\w*)\s*\(", lines[n]):
                if call in seen or call in ("assertThat", "assertEquals", "assertTrue", "start", "stop"):
                    continue
                seen.add(call)
                b = method_bounds(lines, call)
                if b and b != bounds:
                    sub = assumes_in(lines, b, depth + 1, seen)
                    if sub:
                        return ["via helper %s(): %s" % (call, x) for x in sub]
    return out


def reason_for(module_dir, classname, name, message, body):
    if message and message.strip():
        return message.strip().splitlines()[0]
    lines = source_for(module_dir, classname)
    if lines is None:
        return "no message in report and test source not found"
    method = re.split(r"[\[(]", name)[0].strip()
    bounds = method_bounds(lines, method)
    reasons = []
    if bounds:
        reasons += annotations_before(lines, bounds[0])
        reasons += assumes_in(lines, bounds)
    if not reasons:
        simple = classname.split(".")[-1].split("$")[-1]
        for i, line in enumerate(lines):
            if re.search(r"\bclass\s+" + re.escape(simple) + r"\b", line):
                reasons += annotations_before(lines, i)
                break
    if not reasons and body and "Assumption" in body:
        reasons.append("JUnit assumption aborted the test (" + body.strip().splitlines()[0][:160] + ")")
    if not reasons:
        return "skipped by JUnit with no message; no disabling annotation or assumption found in source"
    return "; ".join(dict.fromkeys(reasons))


LAST_MODULE = "jetty-client"

# Skips whose condition cannot be satisfied by the build environment; the generic
# report message alone does not say why.
NOTES = {
    ("org.eclipse.jetty.util.URLEncodedTest", "testCharsetViaSystemProperty"):
        "upstream @EnabledIfSystemProperty(named=org.eclipse.jetty.util.UrlEncoding.charset, matches=\\p{Alnum}): "
        "the regex is a full match on ONE alphanumeric character, so no real charset name can enable it; and UrlEncoded "
        "reads that property once in a static initializer, so setting it would change the charset of every other "
        "jetty-util test. Not run by upstream CI either (property never set in pom/Jenkinsfile)",
}

DISABLED_RE = re.compile(r"^(public |protected |private )?.*?(\w+)\(.*\) (throws [\w.]+ )?is @Disabled$")


def normalize(cls, meth, reason):
    note = NOTES.get((cls, meth))
    if note:
        return note
    if DISABLED_RE.match(reason) or reason.endswith(" is @Disabled"):
        if reason.startswith("class "):
            return "upstream @Disabled on the whole test class (annotation carries no text)"
        return "upstream @Disabled on the test method (annotation carries no text)"
    if reason.startswith("Disabled on JRE version") and cls.endswith("SPNEGOAuthenticationTest"):
        return ("upstream @DisabledOnJre(JAVA_8..10) - source comment: only JDK 11 can run these Kerberos tests "
                "(JDK-8202439, AES intrinsics); they are executed in this workflow's client-jdk11 job instead")
    if reason.startswith("Disabled on JRE version"):
        return "upstream @DisabledOnJre: " + reason
    if reason.startswith("Disabled on operating system"):
        return "upstream @DisabledOnOs (Windows-only test): " + reason
    if "assume" in reason.lower():
        return "JUnit assumption in upstream test source: " + reason
    return reason


def main():
    modules = collections.OrderedDict()
    groups = collections.OrderedDict()
    for xml in sorted(glob.glob(os.path.join(ROOT, "**", "target", "surefire-reports", "TEST-*.xml"), recursive=True)):
        module_dir = xml.split(os.sep + "target" + os.sep)[0]
        mod = os.path.relpath(module_dir, ROOT)
        stats = modules.setdefault(mod, collections.Counter())
        try:
            root = ET.parse(xml).getroot()
        except ET.ParseError as exc:
            print("WARN: cannot parse %s: %s" % (xml, exc))
            continue
        for tc in root.iter("testcase"):
            stats["run"] += 1
            if tc.find("failure") is not None:
                stats["failures"] += 1
            elif tc.find("error") is not None:
                stats["errors"] += 1
            elif tc.find("skipped") is not None:
                stats["skipped"] += 1
                sk = tc.find("skipped")
                cls = tc.get("classname", "?")
                reason = reason_for(module_dir, cls, tc.get("name", "?"), sk.get("message"), sk.text)
                key = (mod, cls, re.split(r"[\[(]", tc.get("name", "?"))[0], reason)
                groups[key] = groups.get(key, 0) + 1
            else:
                stats["passed"] += 1

    # Collapse to one line per (module, class, reason); the target module is printed last.
    collapsed = collections.OrderedDict()
    for (mod, cls, meth, reason), count in groups.items():
        reason = normalize(cls, meth, reason)
        entry = collapsed.setdefault((mod, cls, reason), [collections.OrderedDict(), 0])
        entry[0][meth] = True
        entry[1] += count
    order = sorted({k[0] for k in collapsed}, key=lambda m: (m == LAST_MODULE, m))
    print("=" * 100)
    print("SKIPPED TESTS, one line per class and reason (module | class [methods] xN -> reason)")
    print("=" * 100)
    for mod in order:
        for (m, cls, reason), (meths, count) in collapsed.items():
            if m == mod:
                print("SKIP %s | %s [%s] x%d -> %s" % (mod, cls.split(".")[-1], ",".join(meths), count, reason))
    print("=" * 100)
    print("PER-MODULE SUREFIRE RESULTS")
    print("=" * 100)
    total = collections.Counter()
    for mod, st in modules.items():
        total.update(st)
        print("MODULE %-30s run=%5d passed=%5d failures=%d errors=%d skipped=%d"
              % (mod, st["run"], st["passed"], st["failures"], st["errors"], st["skipped"]))
    print("TOTALS: run=%d passed=%d failures=%d errors=%d skipped=%d"
          % (total["run"], total["passed"], total["failures"], total["errors"], total["skipped"]))
    if total["failures"] or total["errors"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
