#pragma once

// Listener policy for obsidian_server: where it may bind, who may connect, and
// what it refuses outright.
//
// WHY THIS IS A SEPARATE, WINDOWS-FREE HEADER
//
// Everything here is a string or integer decision -- no sockets, no Schannel,
// no <Windows.h>. That is deliberate. The rest of the server cannot be built
// or run anywhere but Windows with the x64dbg SDK present, so for most of this
// project's life the C++ has been verified by reading. The decisions that
// matter for security are exactly the ones in this file, and keeping them free
// of platform dependencies lets tests/test_cpp_listener_policy.py #include this
// header, compile it with g++ and RUN it -- against the shipped source, not a
// transcription of it.
//
// THE POLICY, which mirrors src/utils/remote.py on the Python side:
//
//   * Loopback by default, and a loopback bind needs no opt-in.
//   * A non-loopback bind REQUIRES TLS. There is no flag combination that
//     serves plaintext to another host: the token and every memory write it
//     authorises would cross the network in the clear.
//   * A wildcard bind (0.0.0.0, ::, *, empty) is refused outright, with or
//     without TLS. "Expose this to every interface" must never be reachable by
//     typo; an operator who wants LAN access names the interface.
//   * An address this file cannot classify is refused rather than handed to
//     the OS. inet_addr accepts forms this parser does not ("0", "0177.0.0.1",
//     "127.1"), and a classifier that disagrees with the thing that actually
//     binds is a classifier that can be walked past -- the same reasoning as
//     the cmdsplit mirror in the x64dbg bridge.
//
// The listener is IPv4-only, as it has always been: the server creates an
// AF_INET socket and binds a sockaddr_in. The wildcard check still recognises
// the IPv6 spellings so that "::" is refused with a clear message rather than
// failing later as an unparseable address.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace Listener {

// What the plugin has always spawned, and what the Python bridge defaults to.
static const int DEFAULT_PORT = 8765;
static const char* const DEFAULT_BIND = "127.0.0.1";

// An address range that may connect, as a host-order network and mask.
struct Cidr {
    uint32_t network;
    uint32_t mask;
};

struct Options {
    std::string bind = DEFAULT_BIND;
    int port = DEFAULT_PORT;

    // SHA-1 thumbprint (40 hex characters, as PowerShell prints it) of the
    // server certificate, looked up in a Windows certificate store. A
    // thumbprint rather than a PEM path on purpose: it needs no parser in this
    // process, and New-SelfSignedCertificate hands the operator one directly.
    std::string tlsCertThumbprint;

    // Thumbprint of the CA that must have issued a client certificate. Setting
    // it turns on mutual TLS, so a client without such a certificate fails the
    // handshake before any HTTP is read.
    std::string tlsClientCaThumbprint;

    // Look in LOCAL_MACHINE\MY instead of CURRENT_USER\MY.
    bool machineStore = false;

    // Empty means any peer that completes TLS may present a token.
    std::vector<Cidr> clientAllowlist;

    // Extra Host/Origin values to accept beyond the bind address, for clients
    // that dial a DNS name.
    std::vector<std::string> allowedHosts;

    bool TlsEnabled() const { return !tlsCertThumbprint.empty(); }
    bool MutualTls() const { return !tlsClientCaThumbprint.empty(); }
};

// Address parsing

// Strict dotted-quad parse into a host-order address.
//
// Strict means: exactly four octets, one to three decimal digits each, no
// leading zeros ("01" is refused), each octet <= 255, and nothing else in the
// string. Everything inet_addr would additionally accept is refused, because
// the point of this function is to agree with the bind call, and the only way
// to guarantee that is to narrow the accepted set to the unambiguous one.
inline bool ParseIPv4(const std::string& text, uint32_t& outAddr) {
    outAddr = 0;
    uint32_t octets[4] = {0, 0, 0, 0};
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        if (i > 0) {
            if (pos >= text.size() || text[pos] != '.') return false;
            pos++;
        }
        size_t digitStart = pos;
        uint32_t value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            value = value * 10 + static_cast<uint32_t>(text[pos] - '0');
            pos++;
            if (pos - digitStart > 3) return false;
        }
        size_t digits = pos - digitStart;
        if (digits == 0) return false;
        // A leading zero makes the value ambiguous: inet_addr reads "010" as
        // octal 8, this parser would read 10, and the two must never disagree.
        if (digits > 1 && text[digitStart] == '0') return false;
        if (value > 255) return false;
        octets[i] = value;
    }
    if (pos != text.size()) return false;
    outAddr = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
}

// Lowercase a string, ASCII only. Not tolower(): that honours the C locale,
// and a locale-dependent host comparison is a bug waiting for a non-English
// host (the same reason AsciiEqualsIgnoreCase exists in main.cpp).
inline std::string AsciiLower(const std::string& text) {
    std::string out = text;
    for (size_t i = 0; i < out.size(); i++) {
        char c = out[i];
        if (c >= 'A' && c <= 'Z') out[i] = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

inline std::string Trim(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) begin++;
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) end--;
    return text.substr(begin, end - begin);
}

// Strip IPv6 brackets, leaving the bare name or address.
inline std::string Unbracket(const std::string& text) {
    if (text.size() >= 2 && text[0] == '[' && text[text.size() - 1] == ']') {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

// Does this ask to bind every interface? Every spelling that means "anywhere"
// to some layer, including the IPv6 ones this server cannot bind at all.
inline bool IsWildcardBind(const std::string& text) {
    const std::string host = AsciiLower(Unbracket(Trim(text)));
    if (host.empty() || host == "*" || host == "::" || host == "0:0:0:0:0:0:0:0") {
        return true;
    }
    uint32_t addr = 0;
    if (ParseIPv4(host, addr)) {
        return addr == 0;
    }
    return false;
}

// Is this an address that only reaches this machine? The whole 127.0.0.0/8
// range, not an equality check against 127.0.0.1 -- 127.0.0.2 is loopback too.
inline bool IsLoopbackBind(const std::string& text) {
    const std::string host = AsciiLower(Unbracket(Trim(text)));
    if (host == "::1") {
        return true;
    }
    uint32_t addr = 0;
    if (!ParseIPv4(host, addr)) {
        return false;
    }
    return (addr & 0xFF000000u) == 0x7F000000u;
}

// Parse "10.0.0.0/24" or a bare "10.0.0.7" (which becomes a single host).
// A bare address is accepted because "allow this one client" is the common
// case, and making an operator write /32 invites the typo that locks them out.
inline bool ParseCidr(const std::string& text, Cidr& outCidr, std::string& outError) {
    const std::string entry = Trim(text);
    const size_t slash = entry.find('/');
    std::string addrPart = (slash == std::string::npos) ? entry : entry.substr(0, slash);
    int prefix = 32;

    if (slash != std::string::npos) {
        const std::string prefixPart = entry.substr(slash + 1);
        if (prefixPart.empty() || prefixPart.size() > 2) {
            outError = "prefix length must be 0-32 in '" + entry + "'";
            return false;
        }
        for (size_t i = 0; i < prefixPart.size(); i++) {
            if (prefixPart[i] < '0' || prefixPart[i] > '9') {
                outError = "prefix length is not a number in '" + entry + "'";
                return false;
            }
        }
        prefix = atoi(prefixPart.c_str());
        if (prefix < 0 || prefix > 32) {
            outError = "prefix length must be 0-32 in '" + entry + "'";
            return false;
        }
    }

    uint32_t addr = 0;
    if (!ParseIPv4(addrPart, addr)) {
        outError = "'" + entry + "' is not a dotted-quad IPv4 address or CIDR";
        return false;
    }

    // Shifting by 32 is undefined behaviour, so /0 is spelled out.
    const uint32_t mask =
        (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));

    // Host bits outside the mask are refused rather than masked away.
    // "--allow-client 10.0.0.5/24" means one analyst's box to whoever typed
    // it; reading it as 10.0.0.0/24 admits 254 more addresses and reports
    // nothing. The single-host case needs no prefix at all, so there is no
    // legitimate spelling this rejects.
    if ((addr & ~mask) != 0u) {
        outError = "'" + entry + "' sets bits below the /" +
                   std::to_string(prefix) +
                   " prefix; write the network address, or drop the prefix for "
                   "a single host";
        return false;
    }

    outCidr.network = addr & mask;
    outCidr.mask = mask;
    return true;
}

// May this peer connect? An empty allowlist means yes -- the token and TLS are
// then the only gates, which is the documented default.
inline bool ClientAllowed(const Options& options, uint32_t clientAddr) {
    if (options.clientAllowlist.empty()) {
        return true;
    }
    for (size_t i = 0; i < options.clientAllowlist.size(); i++) {
        const Cidr& range = options.clientAllowlist[i];
        if ((clientAddr & range.mask) == range.network) {
            return true;
        }
    }
    return false;
}

// Host / Origin validation (DNS rebinding)

// Return the host part of a Host-header value, without its port.
//
// Host arrives as "192.168.1.50:8765", "[::1]:8765", "name:8765" or bare. A
// bare IPv6 literal has several colons and no brackets, which is why only the
// single-colon case is split -- splitting "::1" on ':' would leave an empty
// host and refuse a legitimate request.
inline std::string StripHostPort(const std::string& value) {
    std::string host = AsciiLower(Trim(value));
    if (!host.empty() && host[0] == '[') {
        const size_t close = host.find(']');
        if (close != std::string::npos) {
            return host.substr(1, close - 1);
        }
        return host.substr(1);
    }
    size_t colons = 0;
    for (size_t i = 0; i < host.size(); i++) {
        if (host[i] == ':') colons++;
    }
    if (colons == 1) {
        return host.substr(0, host.find(':'));
    }
    return host;
}

// Return the host of an Origin value ("https://host:port").
inline std::string StripOrigin(const std::string& value) {
    const std::string origin = AsciiLower(Trim(value));
    if (origin == "null") {
        return origin;
    }
    // Split on the FIRST "://" and stop at the first delimiter that ends an
    // authority. rfind("//") read "https://evil.test/a//127.0.0.1" as host
    // "127.0.0.1", which a loopback listener answers for -- the parser
    // accepted an origin the check exists to reject. No conforming browser
    // puts a path in Origin, so this was not reachable from the attacker the
    // check is written for; it is fixed because a gate that parses its input
    // differently from what it guards is the defect either way.
    const size_t scheme = origin.find("://");
    std::string authority =
        (scheme == std::string::npos) ? origin : origin.substr(scheme + 3);
    const size_t end = authority.find_first_of("/?#");
    if (end != std::string::npos) {
        authority.erase(end);
    }
    return StripHostPort(authority);
}

// How many times does this header name appear in the request's header section?
//
// Used to refuse a duplicate Host or Origin rather than silently deciding on
// the first one. HTTP/1.1 permits exactly one Host, so a second is malformed
// input -- and in the supported deployment where a TLS terminator sits in front
// of a loopback listener, "the proxy decides on one value and this server
// decides on another" is precisely how a gate gets walked past. The Python gate
// (src/utils/remote.py) refuses duplicates for the same reason; this is the
// other half of that decision.
//
// Mirrors FindHeaderValue's scan in main.cpp: bounded to the header section,
// anchored at the start of a line, case-insensitive up to the colon, and the
// request line skipped so "GET /Host: x HTTP/1.1" is not a header.
inline size_t CountHeaderOccurrences(const std::string& request,
                                     const std::string& name) {
    const std::string wanted = AsciiLower(name);

    size_t limit = request.find("\r\n\r\n");
    if (limit == std::string::npos) {
        limit = request.size();
    }

    size_t lineStart = request.find("\r\n");
    if (lineStart == std::string::npos || lineStart >= limit) {
        return 0;
    }
    lineStart += 2;

    size_t count = 0;
    while (lineStart < limit) {
        size_t lineEnd = request.find("\r\n", lineStart);
        if (lineEnd == std::string::npos || lineEnd > limit) {
            lineEnd = limit;
        }
        if (lineEnd == lineStart) {
            break;  // blank line: end of the header section
        }
        const size_t colon = request.find(':', lineStart);
        if (colon != std::string::npos && colon < lineEnd) {
            if (AsciiLower(request.substr(lineStart, colon - lineStart)) == wanted) {
                count++;
            }
        }
        if (lineEnd == limit) {
            break;
        }
        lineStart = lineEnd + 2;
    }
    return count;
}

// Is this a Host/Origin value the listener answers for?
//
// This is the DNS-rebinding control. Without it, a browser on any host that can
// resolve a name to this address could drive the debugger through a page the
// operator never visited; the response headers no longer invite that (the
// Access-Control-Allow-Origin wildcard is gone), but a check that refuses the
// request outright is the part that does not depend on browser behaviour.
inline bool HostAllowed(const Options& options, const std::string& hostValue) {
    const std::string host = StripHostPort(hostValue);
    if (host.empty()) {
        return false;
    }
    // options.bind is already lowercased and unbracketed by ParseOptions, and
    // Describe/ParseIPv4/main.cpp all read that same value.
    if (host == options.bind) {
        return true;
    }
    // A loopback listener answers for every spelling of itself: a client may
    // dial any of them and reach it, so refusing the others is a false
    // positive. Spellings outside 127.0.0.0/8 are not included -- 127.0.0.2
    // reaches a 127.0.0.1 listener on Windows, but accepting a Host nobody
    // dials buys nothing.
    if (IsLoopbackBind(options.bind)) {
        if (host == "localhost" || host == "127.0.0.1" || host == "::1") {
            return true;
        }
    }
    for (size_t i = 0; i < options.allowedHosts.size(); i++) {
        if (host == AsciiLower(options.allowedHosts[i])) {
            return true;
        }
    }
    return false;
}

// Command line

// A pinned bearer token has to be long enough to be worth pinning. The
// generated one is 64 hex characters and dies when x64dbg unloads; a pinned one
// lives as long as the ini file does, so a short one is a real downgrade rather
// than a convenience, and it is refused at start-up instead of served.
static const size_t MIN_PINNED_TOKEN_LENGTH = 32;

// Upper bound chosen against the reader, not the protocol. The plugin reads
// this key with a 512-byte GetPrivateProfileString buffer, which TRUNCATES
// silently -- and a truncated token is served happily by this half while the
// bridge presents the full one, producing "Invalid token (wrong length)" with
// nothing pointing at the ini. Refusing well under the buffer means a value
// that was truncated cannot be mistaken for a valid one.
static const size_t MAX_PINNED_TOKEN_LENGTH = 256;

// May this be used as a pinned bearer token?
//
// The character set is RFC 6750 token68, which is exactly what
// src/utils/remote.py enforces on OBSIDIAN_AUTH_TOKEN (_TOKEN_CHARS). The two
// have to agree: a token this accepts and the bridge then refuses leaves an
// operator with a listener that works, a client that will not talk to it, and
// nothing naming the disagreement -- the same class of defect as a classifier
// that reads an address differently from the thing that binds it.
// tests/test_cpp_listener_policy.py asserts the two sets still match.
inline bool IsPinnedToken(const std::string& token, std::string& outError) {
    if (token.size() < MIN_PINNED_TOKEN_LENGTH) {
        outError = "token is " + std::to_string(token.size()) +
                   " characters; a pinned token must be at least " +
                   std::to_string(MIN_PINNED_TOKEN_LENGTH) +
                   " because it outlives the session, unlike the generated one";
        return false;
    }
    if (token.size() > MAX_PINNED_TOKEN_LENGTH) {
        outError = "token is longer than " +
                   std::to_string(MAX_PINNED_TOKEN_LENGTH) +
                   " characters; shorten it, or it cannot be distinguished from "
                   "one the ini reader truncated";
        return false;
    }
    for (size_t i = 0; i < token.size(); i++) {
        const char c = token[i];
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                        c == '_' || c == '~' || c == '+' || c == '/' || c == '=';
        if (!ok) {
            outError = "token contains a character a bearer token may not hold; "
                       "allowed: letters, digits and - . _ ~ + / = "
                       "(RFC 6750 token68)";
            return false;
        }
    }
    return true;
}

// Is this 40 hex characters, as a SHA-1 certificate thumbprint must be?
// Checked here rather than at the store lookup so a typo is a start-up refusal
// with a clear message instead of "certificate not found".
inline bool IsThumbprint(const std::string& text) {
    if (text.size() != 40) {
        return false;
    }
    for (size_t i = 0; i < text.size(); i++) {
        const char c = text[i];
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

// Strip the separators PowerShell and certmgr put in a thumbprint when copied
// from the UI, so an operator pasting "ab:cd ef..." is not told it is a typo.
inline std::string NormalizeThumbprint(const std::string& text) {
    std::string out;
    for (size_t i = 0; i < text.size(); i++) {
        const char c = text[i];
        if (c == ':' || c == ' ' || c == '-') continue;
        out.push_back(c);
    }
    return AsciiLower(out);
}

inline bool ParsePort(const std::string& text, int& outPort, std::string& outError) {
    if (text.empty()) {
        outError = "port is empty";
        return false;
    }
    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] < '0' || text[i] > '9') {
            outError = "port '" + text + "' is not a number";
            return false;
        }
    }
    const long value = strtol(text.c_str(), nullptr, 10);
    if (value < 1 || value > 65535) {
        outError = "port '" + text + "' is outside 1-65535";
        return false;
    }
    outPort = static_cast<int>(value);
    return true;
}

// Parse argv into Options, then enforce the policy.
//
// A bare numeric first argument is still accepted as the port: that is how this
// executable has always been invoked, and breaking it would break every
// deployed plugin that spawns it.
//
// Returns false with outError set on anything it will not serve. The caller
// exits; it does not fall back to a default, because a listener that comes up
// differently from how it was asked to is worse than one that refuses.
inline bool ParseOptions(int argc, const char* const* argv, Options& outOptions,
                         std::string& outError) {
    Options options;

    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i] ? argv[i] : "";

        // Legacy positional port.
        if (i == 1 && !arg.empty() && arg[0] != '-') {
            if (!ParsePort(arg, options.port, outError)) return false;
            continue;
        }

        const bool needsValue =
            (arg == "--bind" || arg == "--port" || arg == "--tls-cert-thumbprint" ||
             arg == "--tls-client-ca-thumbprint" || arg == "--allow-client" ||
             arg == "--allow-host");
        std::string value;
        if (needsValue) {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                outError = arg + " needs a value";
                return false;
            }
            value = argv[++i];
        }

        if (arg == "--bind") {
            // Normalised HERE, not at each use. ParseOptions classified
            // "[127.0.0.1]" by unbracketing it and then stored the raw value,
            // so main.cpp's ParseIPv4 on the raw string failed at bind time --
            // exit 1 ("port already in use") instead of the clean exit-2
            // refusal, and the plugin's exit-2 branch never fired. The whole
            // point of one shared parser is that every reader agrees.
            options.bind = AsciiLower(Unbracket(Trim(value)));
        } else if (arg == "--port") {
            if (!ParsePort(Trim(value), options.port, outError)) return false;
        } else if (arg == "--tls-cert-thumbprint") {
            options.tlsCertThumbprint = NormalizeThumbprint(Trim(value));
            if (!IsThumbprint(options.tlsCertThumbprint)) {
                outError = "--tls-cert-thumbprint must be 40 hex characters (a SHA-1 "
                           "certificate thumbprint); got '" + Trim(value) + "'";
                return false;
            }
        } else if (arg == "--tls-client-ca-thumbprint") {
            options.tlsClientCaThumbprint = NormalizeThumbprint(Trim(value));
            if (!IsThumbprint(options.tlsClientCaThumbprint)) {
                outError = "--tls-client-ca-thumbprint must be 40 hex characters; got '" +
                           Trim(value) + "'";
                return false;
            }
        } else if (arg == "--machine-store") {
            options.machineStore = true;
        } else if (arg == "--allow-client") {
            Cidr range;
            std::string cidrError;
            if (!ParseCidr(value, range, cidrError)) {
                // Dropping a malformed entry would silently widen the
                // allowlist, which is the opposite of what it is for.
                outError = "--allow-client " + cidrError;
                return false;
            }
            options.clientAllowlist.push_back(range);
        } else if (arg == "--allow-host") {
            // StripHostPort as well as the usual normalisation, because
            // HostAllowed strips the port from every incoming Host before
            // comparing. An entry written as "analysis.lan:8765" -- the
            // obvious thing to copy from the URL a client dials -- would
            // otherwise sit in the list matching nothing, and the refusal
            // would name a host the operator had already allowed.
            const std::string host = StripHostPort(AsciiLower(Unbracket(Trim(value))));
            if (host.empty()) {
                outError = "--allow-host needs a non-empty value";
                return false;
            }
            options.allowedHosts.push_back(host);
        } else {
            outError = "unknown argument '" + arg + "'";
            return false;
        }
    }

    // Policy checks. The legacy positional port and --port are accepted
    // either way, so nothing below distinguishes them.

    if (IsWildcardBind(options.bind)) {
        outError =
            "--bind " + options.bind +
            " binds every interface, which is refused even with TLS configured. "
            "Name the interface address this server should be reachable on, or "
            "omit --bind for " + std::string(DEFAULT_BIND) + ".";
        return false;
    }

    const bool loopback = IsLoopbackBind(options.bind);

    // Both checks below are predicates, not conversions: main.cpp parses the
    // address again at bind time, so the value is not wanted here. And
    // options.bind is already AsciiLower(Unbracket(Trim(...))) from the
    // --bind branch above -- re-normalising it here would reintroduce exactly
    // the per-use normalisation that caused the classifier and the binder to
    // read different strings.
    uint32_t ignored = 0;
    if (!loopback && !ParseIPv4(options.bind, ignored)) {
        outError = "--bind " + options.bind +
                   " is not a dotted-quad IPv4 address. This listener binds "
                   "AF_INET numerically and does not resolve names; give the "
                   "interface's address.";
        return false;
    }
    if (loopback && !ParseIPv4(options.bind, ignored)) {
        // "::1" classifies as loopback but cannot be bound by an AF_INET
        // socket. Refusing here beats failing in bind() with WSAEFAULT.
        outError = "--bind " + options.bind +
                   " is an IPv6 address; this listener is IPv4-only. Use 127.0.0.1.";
        return false;
    }

    if (!loopback && !options.TlsEnabled()) {
        outError =
            "--bind " + options.bind +
            " is not a loopback address, so TLS is required: pass "
            "--tls-cert-thumbprint. Without it the bearer token, and every "
            "memory write it authorises, crosses the network in cleartext.";
        return false;
    }

    if (options.MutualTls() && !options.TlsEnabled()) {
        outError =
            "--tls-client-ca-thumbprint asks for client-certificate "
            "verification, but --tls-cert-thumbprint is unset so there is no "
            "TLS to verify within.";
        return false;
    }

    outOptions = options;
    return true;
}

// One line for the start-up log, naming what is NOT on rather than what is: a
// line that lists only what is enabled reads the same whether TLS is off or on.
inline std::string Describe(const Options& options) {
    std::string out = (options.TlsEnabled() ? "https://" : "http://") + options.bind +
                      ":" + std::to_string(options.port);
    out += options.MutualTls() ? " tls=mutual"
                               : (options.TlsEnabled() ? " tls=server" : " tls=OFF");
    out += options.clientAllowlist.empty()
               ? " client-allowlist=OFF"
               : " client-allowlist=" + std::to_string(options.clientAllowlist.size());
    out += IsLoopbackBind(options.bind) ? " loopback" : " REMOTE";
    return out;
}

// The usage text, printed on a refusal so the operator sees the whole surface
// rather than guessing the flag that would have worked.
inline const char* UsageText() {
    return
        "obsidian_server [<port>] [options]\n"
        "\n"
        "  --bind <ipv4>                     interface to listen on "
        "(default 127.0.0.1; 0.0.0.0 is refused)\n"
        "  --port <n>                        port to listen on (default 8765)\n"
        "  --tls-cert-thumbprint <hex40>     server certificate, by SHA-1 "
        "thumbprint; required off loopback\n"
        "  --tls-client-ca-thumbprint <hex40>  require a client certificate "
        "issued by this CA (mutual TLS)\n"
        "  --machine-store                   look in LocalMachine\\MY instead of "
        "CurrentUser\\MY\n"
        "  --allow-client <ipv4[/prefix]>    only this address or range may "
        "connect (repeatable)\n"
        "  --allow-host <name>               extra Host/Origin value to accept "
        "(repeatable)\n";
}

}  // namespace Listener
