#pragma once

// TLS for obsidian_server, via Schannel (SSPI).
//
// WHY SCHANNEL AND NOT A LIBRARY
//
// These binaries get copied into an analyst's x64dbg plugins directory and are
// verified against a published SHA-256 by install.ps1. Every third-party
// dependency added here is another thing to vendor, pin, update and explain in
// the supply-chain section of INSTALL.md. Schannel ships with Windows: it costs
// two import libraries (secur32, crypt32) and no new artifact.
//
// WHAT THIS DELIBERATELY DOES NOT DO
//
//   * TLS 1.3. That needs SCH_CREDENTIALS, which exists only on newer SDKs and
//     carries a second code path. TLS 1.2 with SCH_USE_STRONG_CRYPTO is what is
//     negotiated here: universally available, and adequate for a link between
//     two machines on an analyst's own network. Moving to SCH_CREDENTIALS is a
//     contained change when it is worth making.
//   * Renegotiation. A mid-stream SEC_I_RENEGOTIATE is answered by closing the
//     connection. This API has no long-lived connections (one request per
//     connection) and renegotiation has a long history of being the subtle part
//     of a TLS implementation. Refusing is both safe and correct here.
//   * Session tickets or resumption tuning. Schannel's own session cache
//     handles that, which is the main reason this server can afford a handshake
//     per request: a resumed handshake is one round trip and no asymmetric
//     operation.
//
// CERTIFICATES ARE NAMED BY THUMBPRINT, not by a PEM path, so this process
// needs no certificate parser. PowerShell's New-SelfSignedCertificate prints a
// thumbprint; install.ps1 passes it straight through.

#ifndef _WIN32
#error "schannel_tls.h is Windows-only; guard its inclusion"
#endif

#define SECURITY_WIN32

#include <winsock2.h>
#include <Windows.h>
#include <wincrypt.h>
#include <schannel.h>
#include <sspi.h>

#include <string>
#include <vector>

// Declared in main.cpp. Every failure path here logs, because a TLS failure
// that is invisible is indistinguishable from a network problem.
void Log(const char* format, ...);

namespace Tls {

// Largest TLS record payload plus Schannel's header and trailer. Queried from
// the context after the handshake; this is only the initial buffer reservation.
static const size_t INITIAL_IO_BUFFER = 32 * 1024;

// Wall-clock budget for completing a handshake, mirroring main.cpp's
// REQUEST_DEADLINE_MS for the request that follows it.
//
// Both exist because Read() and Handshake() loop recv() internally, which the
// request reader in main.cpp cannot see. That reader checks its deadline only
// BETWEEN conn.Recv() calls; on the plaintext path recv returns as soon as any
// byte arrives, so the check fires. On the TLS path DecryptAvailable re-reads
// on a partial record and Read re-reads while no plaintext has emerged, so a
// peer sending one byte every four seconds -- under the 5 s SO_RCVTIMEO --
// never returned control to it. The server handles one connection at a time,
// so that was a single unauthenticated peer denying the whole bridge.
static const unsigned long long HANDSHAKE_DEADLINE_MS = 15000;

// Convert 40 hex characters into the 20 raw bytes CERT_FIND_HASH wants.
inline bool ThumbprintToBytes(const std::string& hex, BYTE* out20) {
    if (hex.size() != 40) {
        return false;
    }
    for (size_t i = 0; i < 20; i++) {
        int value = 0;
        for (size_t nibble = 0; nibble < 2; nibble++) {
            const char c = hex[i * 2 + nibble];
            int digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            value = (value << 4) | digit;
        }
        out20[i] = static_cast<BYTE>(value);
    }
    return true;
}

// Open CURRENT_USER\MY or LOCAL_MACHINE\MY and find one certificate by
// thumbprint. The caller owns the returned context.
inline PCCERT_CONTEXT FindCertificate(const std::string& thumbprint, bool machineStore) {
    BYTE hash[20];
    if (!ThumbprintToBytes(thumbprint, hash)) {
        Log("TLS: thumbprint is not 40 hex characters");
        return nullptr;
    }

    const DWORD storeFlags =
        (machineStore ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER) |
        CERT_STORE_READONLY_FLAG;

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, storeFlags, "MY");
    if (store == nullptr) {
        Log("TLS: cannot open the %s certificate store (error %lu)",
            machineStore ? "LocalMachine" : "CurrentUser", GetLastError());
        return nullptr;
    }

    CRYPT_HASH_BLOB blob;
    blob.cbData = 20;
    blob.pbData = hash;

    PCCERT_CONTEXT cert = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &blob, nullptr);

    if (cert == nullptr) {
        Log("TLS: no certificate with that thumbprint in %s\\MY. "
            "Check the store (--machine-store selects LocalMachine) and that the "
            "certificate has a private key.",
            machineStore ? "LocalMachine" : "CurrentUser");
    }

    // The store can be closed while a certificate context from it is held:
    // the context keeps its own reference.
    CertCloseStore(store, 0);
    return cert;
}

// Process-wide server credentials. Acquired once at start-up so a bad
// certificate is a start-up refusal rather than a failure on first connect.
class ServerCredentials {
public:
    ServerCredentials() {
        SecInvalidateHandle(&m_credentials);
    }

    ~ServerCredentials() {
        if (SecIsValidHandle(&m_credentials)) {
            FreeCredentialsHandle(&m_credentials);
        }
        if (m_cert != nullptr) {
            CertFreeCertificateContext(m_cert);
        }
    }

    bool Acquire(const std::string& certThumbprint, bool machineStore,
                 bool requireClientCert) {
        m_cert = FindCertificate(certThumbprint, machineStore);
        if (m_cert == nullptr) {
            return false;
        }

        SCHANNEL_CRED credentials = {};
        credentials.dwVersion = SCHANNEL_CRED_VERSION;
        credentials.cCreds = 1;
        credentials.paCred = &m_cert;
        credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
        // SCH_USE_STRONG_CRYPTO drops the cipher suites Windows keeps for
        // compatibility. There is nothing old on the other end of this link --
        // it is this project's own Python client -- so there is no reason to
        // offer them.
        credentials.dwFlags = SCH_USE_STRONG_CRYPTO;
        if (requireClientCert) {
            // Ask for the client's certificate during the handshake AND fail
            // the handshake when it is absent. Without SCH_CRED_NO_SYSTEM_MAPPER
            // Schannel would also try to map it to a Windows account, which is
            // not what is wanted: the chain check below is the authority.
            credentials.dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;
        }

        const SECURITY_STATUS status = AcquireCredentialsHandleA(
            nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_INBOUND, nullptr,
            &credentials, nullptr, nullptr, &m_credentials, nullptr);

        if (status != SEC_E_OK) {
            Log("TLS: AcquireCredentialsHandle failed (0x%08lx). A certificate "
                "without an accessible private key is the usual cause.",
                static_cast<unsigned long>(status));
            return false;
        }

        Log("TLS: server credentials acquired (TLS 1.2, strong crypto%s)",
            requireClientCert ? ", client certificate required" : "");
        return true;
    }

    CredHandle* Handle() { return &m_credentials; }

private:
    ServerCredentials(const ServerCredentials&);
    ServerCredentials& operator=(const ServerCredentials&);

    PCCERT_CONTEXT m_cert = nullptr;
    CredHandle m_credentials;
};

// Verify that a client certificate chains to the configured CA and that the
// chain itself is sound.
//
// Schannel having accepted the certificate is NOT the check: with
// SCH_CRED_NO_SYSTEM_MAPPER it validates the chain against the machine's trust
// stores, which is a much broader set than "the CA an analyst made for this
// lab". Pinning to one thumbprint is the whole point of the flag.
inline bool ClientCertificateChainsTo(PCCERT_CONTEXT clientCert,
                                      const std::string& caThumbprint) {
    BYTE wantedHash[20];
    if (!ThumbprintToBytes(caThumbprint, wantedHash)) {
        Log("TLS: client CA thumbprint is not 40 hex characters");
        return false;
    }

    // Require the certificate to be valid FOR CLIENT AUTHENTICATION, not
    // merely valid.
    //
    // With RequestedUsage left zeroed, CertGetCertificateChain checks the
    // chain but not what the certificate is for -- so a SERVER certificate
    // issued by the pinned CA would authenticate as a client. That matters
    // whenever the pin is anything broader than a CA made solely for this
    // purpose: against an enterprise CA, every server certificate it ever
    // issued becomes a valid client credential here.
    //
    // OpenSSL enforces this on the Python listener already (a serverAuth-only
    // certificate from the configured CA is rejected there), so without this
    // the two halves of the same policy disagreed about the same certificate.
    // A usage mismatch surfaces as CERT_TRUST_IS_NOT_VALID_FOR_USAGE, which
    // the dwErrorStatus check below already treats as fatal.
    LPSTR clientAuthOid[] = {const_cast<LPSTR>(szOID_PKIX_KP_CLIENT_AUTH)};

    CERT_CHAIN_PARA chainParameters = {};
    chainParameters.cbSize = sizeof(chainParameters);
    chainParameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    chainParameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainParameters.RequestedUsage.Usage.rgpszUsageIdentifier = clientAuthOid;

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, clientCert, nullptr, nullptr,
                                 &chainParameters, 0, nullptr, &chain)) {
        Log("TLS: cannot build a chain for the client certificate (error %lu)",
            GetLastError());
        return false;
    }

    bool accepted = false;
    do {
        // Nothing is tolerated here, including CERT_TRUST_IS_UNTRUSTED_ROOT.
        // That means the pinned CA must also be installed in a trust store the
        // server process can read -- the thumbprint pin is an ADDITIONAL
        // restriction on top of chain validity, not a replacement for it.
        //
        // Deliberate: tolerating an untrusted root so the pin could stand
        // alone would need the CA certificate supplied to chain building via
        // hAdditionalStore, and getting that wrong fails open. Requiring the
        // operator to put the CA in CurrentUser\Root fails closed, and scopes
        // that trust to the one account on the debugger VM rather than the
        // machine. docs/remote-access.md spells out the step and its cost.
        const DWORD errorStatus = chain->TrustStatus.dwErrorStatus;
        if (errorStatus != CERT_TRUST_NO_ERROR) {
            Log("TLS: client certificate chain is not trusted (status 0x%08lx). "
                "CERT_TRUST_IS_UNTRUSTED_ROOT (0x20) means the CA is not in a "
                "trust store this process can read.",
                static_cast<unsigned long>(errorStatus));
            break;
        }
        if (chain->cChain == 0 || chain->rgpChain[0]->cElement == 0) {
            Log("TLS: client certificate chain is empty");
            break;
        }

        // The configured CA must appear in the chain. Checked across every
        // element rather than only the root, so an intermediate the operator
        // nominated also works.
        const CERT_SIMPLE_CHAIN* simple = chain->rgpChain[0];
        for (DWORD i = 0; i < simple->cElement; i++) {
            BYTE thisHash[20] = {};
            DWORD hashSize = sizeof(thisHash);
            if (!CertGetCertificateContextProperty(simple->rgpElement[i]->pCertContext,
                                                   CERT_HASH_PROP_ID, thisHash,
                                                   &hashSize)) {
                continue;
            }
            if (hashSize == sizeof(wantedHash) &&
                memcmp(thisHash, wantedHash, sizeof(wantedHash)) == 0) {
                accepted = true;
                break;
            }
        }

        if (!accepted) {
            Log("TLS: client certificate is trusted but was not issued under the "
                "CA named by --tls-client-ca-thumbprint");
        }
    } while (false);

    CertFreeCertificateChain(chain);
    return accepted;
}

// One TLS connection. Owns the security context and the record buffers.
//
// Read/Write present the same contract as recv/send so the request-reading loop
// in main.cpp is unchanged: > 0 is a byte count, 0 is an orderly close, and
// SOCKET_ERROR is a failure. Keeping that contract is what let the audited
// framing code (the F-19 bounds work) stay exactly as it was.
class Channel {
public:
    explicit Channel(SOCKET socket) : m_socket(socket) {
        SecInvalidateHandle(&m_context);
        // No buffer reservation here. main.cpp declares one of these per
        // accepted connection whether or not TLS is configured, so an unused
        // channel must not allocate; Handshake reserves.
    }

    ~Channel() {
        if (SecIsValidHandle(&m_context)) {
            DeleteSecurityContext(&m_context);
        }
    }

    // The instant after which no further recv may be attempted. main.cpp sets
    // this to the request deadline before reading, so the bound covers the
    // whole request and not just one recv.
    void SetDeadline(unsigned long long tickCount) { m_deadline = tickCount; }

    // Run the handshake to completion. Returns false on any failure, having
    // logged why; the caller closes the socket.
    bool Handshake(ServerCredentials& credentials, bool requireClientCert,
                   const std::string& clientCaThumbprint) {
        m_incoming.reserve(INITIAL_IO_BUFFER);
        // The handshake happens before any HTTP exists, so main.cpp has not set
        // a deadline yet. Without one here, a peer could drip bytes at a
        // completed TCP connection forever and never reach the request reader.
        m_deadline = GetTickCount64() + HANDSHAKE_DEADLINE_MS;
        m_credentials = credentials.Handle();

        DWORD contextRequirements = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                    ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
        if (requireClientCert) {
            contextRequirements |= ASC_REQ_MUTUAL_AUTH;
        }

        bool first = true;
        // Nothing is buffered yet, so the first pass must read. Thereafter this
        // is set only when Schannel says it needs more: the previous form
        // (`m_incoming.empty() || !first`) was unconditionally true after the
        // first iteration, so a tail deliberately carried over as
        // SECBUFFER_EXTRA could never be used without first blocking on
        // another recv -- a client pipelining two flights in one write stalled
        // for the full SO_RCVTIMEO and was then abandoned, with the bytes
        // needed to finish already in hand.
        bool needMoreData = true;
        for (;;) {
            if (needMoreData) {
                if (!FillIncoming()) {
                    Log("TLS: peer closed or failed during handshake");
                    return false;
                }
                needMoreData = false;
            }

            SecBuffer inBuffers[2];
            inBuffers[0].pvBuffer = m_incoming.data();
            inBuffers[0].cbBuffer = static_cast<unsigned long>(m_incoming.size());
            inBuffers[0].BufferType = SECBUFFER_TOKEN;
            inBuffers[1].pvBuffer = nullptr;
            inBuffers[1].cbBuffer = 0;
            inBuffers[1].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc inDescriptor;
            inDescriptor.ulVersion = SECBUFFER_VERSION;
            inDescriptor.cBuffers = 2;
            inDescriptor.pBuffers = inBuffers;

            SecBuffer outBuffers[1];
            outBuffers[0].pvBuffer = nullptr;
            outBuffers[0].cbBuffer = 0;
            outBuffers[0].BufferType = SECBUFFER_TOKEN;

            SecBufferDesc outDescriptor;
            outDescriptor.ulVersion = SECBUFFER_VERSION;
            outDescriptor.cBuffers = 1;
            outDescriptor.pBuffers = outBuffers;

            DWORD contextAttributes = 0;
            const SECURITY_STATUS status = AcceptSecurityContext(
                credentials.Handle(), first ? nullptr : &m_context, &inDescriptor,
                contextRequirements, 0, &m_context, &outDescriptor, &contextAttributes,
                nullptr);
            first = false;

            // Anything Schannel produced must go out even on failure: the
            // alert tells the client why, instead of leaving it to time out.
            if (outBuffers[0].pvBuffer != nullptr && outBuffers[0].cbBuffer > 0) {
                const bool sent = SendRaw(static_cast<const char*>(outBuffers[0].pvBuffer),
                                          outBuffers[0].cbBuffer);
                FreeContextBuffer(outBuffers[0].pvBuffer);
                outBuffers[0].pvBuffer = nullptr;
                if (!sent) {
                    Log("TLS: failed to send handshake token");
                    return false;
                }
            }

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                // Need more bytes; keep what we have and read again.
                needMoreData = true;
                continue;
            }

            // Bytes beyond this handshake message belong to the next one, or
            // are already application data. Dropping them is a silent protocol
            // break, so they are carried over.
            // Past SEC_E_INCOMPLETE_MESSAGE, Schannel has consumed the whole
            // input buffer except for whatever it reports as SECBUFFER_EXTRA --
            // which is a count of unconsumed bytes at the END of the buffer, not
            // a pointer to copy from. So: keep the tail, drop the rest.
            //
            // This is unconditional on purpose. Clearing only when the status
            // was not SEC_I_CONTINUE_NEEDED left the just-consumed flight in
            // front of the next one, which is the status where it matters most
            // -- every multi-flight handshake would have re-fed the ClientHello.
            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                const size_t extra = inBuffers[1].cbBuffer;
                m_incoming.erase(m_incoming.begin(),
                                 m_incoming.begin() +
                                     static_cast<std::ptrdiff_t>(m_incoming.size() - extra));
            } else {
                m_incoming.clear();
            }

            if (status == SEC_E_OK) {
                break;
            }
            if (status == SEC_I_CONTINUE_NEEDED) {
                // Read again only if the carried tail is empty.
                needMoreData = m_incoming.empty();
                continue;
            }

            Log("TLS: handshake failed (0x%08lx)", static_cast<unsigned long>(status));
            return false;
        }

        SecPkgContext_StreamSizes sizes = {};
        const SECURITY_STATUS sizeStatus =
            QueryContextAttributes(&m_context, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (sizeStatus != SEC_E_OK) {
            Log("TLS: cannot query stream sizes (0x%08lx)",
                static_cast<unsigned long>(sizeStatus));
            return false;
        }
        m_headerSize = sizes.cbHeader;
        m_trailerSize = sizes.cbTrailer;
        m_maxMessage = sizes.cbMaximumMessage;

        if (requireClientCert && !VerifyClientCertificate(clientCaThumbprint)) {
            return false;
        }

        Log("TLS: handshake complete");
        return true;
    }

    // recv() semantics over the decrypted stream.
    int Read(char* buffer, int length) {
        if (length <= 0) {
            return 0;
        }

        for (;;) {
            // Serve anything already decrypted first.
            if (!m_plaintext.empty()) {
                const size_t take =
                    (m_plaintext.size() < static_cast<size_t>(length))
                        ? m_plaintext.size()
                        : static_cast<size_t>(length);
                memcpy(buffer, m_plaintext.data(), take);
                m_plaintext.erase(m_plaintext.begin(),
                                  m_plaintext.begin() + static_cast<std::ptrdiff_t>(take));
                return static_cast<int>(take);
            }

            if (m_peerClosed) {
                return 0;
            }

            if (m_incoming.empty() && !FillIncoming()) {
                // Orderly close with nothing buffered reads as end of stream,
                // which is what the caller's loop already handles.
                return m_readFailed ? SOCKET_ERROR : 0;
            }

            if (!DecryptAvailable()) {
                return m_readFailed ? SOCKET_ERROR : 0;
            }
        }
    }

    // send() semantics, chunked to the negotiated record size.
    bool Write(const char* data, size_t length) {
        if (m_maxMessage == 0) {
            return false;
        }
        std::vector<char> record;
        size_t offset = 0;
        while (offset < length) {
            const size_t chunk =
                (length - offset < m_maxMessage) ? (length - offset) : m_maxMessage;
            record.assign(m_headerSize + chunk + m_trailerSize, 0);
            memcpy(record.data() + m_headerSize, data + offset, chunk);

            SecBuffer buffers[3];
            buffers[0].pvBuffer = record.data();
            buffers[0].cbBuffer = m_headerSize;
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[1].pvBuffer = record.data() + m_headerSize;
            buffers[1].cbBuffer = static_cast<unsigned long>(chunk);
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[2].pvBuffer = record.data() + m_headerSize + chunk;
            buffers[2].cbBuffer = m_trailerSize;
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

            SecBufferDesc descriptor;
            descriptor.ulVersion = SECBUFFER_VERSION;
            descriptor.cBuffers = 3;
            descriptor.pBuffers = buffers;

            const SECURITY_STATUS status = EncryptMessage(&m_context, 0, &descriptor, 0);
            if (status != SEC_E_OK) {
                Log("TLS: EncryptMessage failed (0x%08lx)",
                    static_cast<unsigned long>(status));
                return false;
            }

            // EncryptMessage may shrink the buffers it was given, so the bytes
            // to send are the sum of the three cbBuffer values, not the size of
            // the vector.
            const size_t total = buffers[0].cbBuffer + buffers[1].cbBuffer +
                                 buffers[2].cbBuffer;
            if (!SendRaw(record.data(), total)) {
                return false;
            }
            offset += chunk;
        }
        return true;
    }

    // Best-effort close_notify, so the peer sees a clean shutdown rather than
    // a truncation it is right to treat as an attack.
    void Shutdown() {
        if (!SecIsValidHandle(&m_context)) {
            return;
        }
        DWORD token = SCHANNEL_SHUTDOWN;
        SecBuffer tokenBuffer;
        tokenBuffer.pvBuffer = &token;
        tokenBuffer.cbBuffer = sizeof(token);
        tokenBuffer.BufferType = SECBUFFER_TOKEN;

        SecBufferDesc tokenDescriptor;
        tokenDescriptor.ulVersion = SECBUFFER_VERSION;
        tokenDescriptor.cBuffers = 1;
        tokenDescriptor.pBuffers = &tokenBuffer;

        if (ApplyControlToken(&m_context, &tokenDescriptor) != SEC_E_OK) {
            return;
        }

        SecBuffer outBuffer;
        outBuffer.pvBuffer = nullptr;
        outBuffer.cbBuffer = 0;
        outBuffer.BufferType = SECBUFFER_TOKEN;

        SecBufferDesc outDescriptor;
        outDescriptor.ulVersion = SECBUFFER_VERSION;
        outDescriptor.cBuffers = 1;
        outDescriptor.pBuffers = &outBuffer;

        // The credentials handle, not nullptr. With nullptr this returns
        // SEC_E_INVALID_HANDLE, outBuffer stays empty and no close_notify is
        // ever produced -- so every TLS connection was torn down by a bare
        // closesocket, which is exactly the truncation this function exists to
        // avoid. Handshake records the handle for this reason.
        DWORD attributes = 0;
        const SECURITY_STATUS status = AcceptSecurityContext(
            m_credentials, &m_context, nullptr,
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, 0, nullptr, &outDescriptor,
            &attributes, nullptr);
        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
            // Best effort: a failed shutdown token is not worth failing the
            // response that has already been sent.
            Log("TLS: shutdown token not produced (0x%08lx)",
                static_cast<unsigned long>(status));
        }

        if (outBuffer.pvBuffer != nullptr && outBuffer.cbBuffer > 0) {
            SendRaw(static_cast<const char*>(outBuffer.pvBuffer), outBuffer.cbBuffer);
            FreeContextBuffer(outBuffer.pvBuffer);
        }
    }

private:
    Channel(const Channel&);
    Channel& operator=(const Channel&);

    bool VerifyClientCertificate(const std::string& caThumbprint) {
        PCCERT_CONTEXT clientCert = nullptr;
        const SECURITY_STATUS status = QueryContextAttributes(
            &m_context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &clientCert);
        if (status != SEC_E_OK || clientCert == nullptr) {
            Log("TLS: mutual TLS is required but the client presented no "
                "certificate (0x%08lx)",
                static_cast<unsigned long>(status));
            return false;
        }
        const bool accepted = ClientCertificateChainsTo(clientCert, caThumbprint);
        CertFreeCertificateContext(clientCert);
        return accepted;
    }

    // Append more ciphertext. False means the peer closed, the socket failed,
    // or the deadline expired; m_readFailed distinguishes a close from the
    // other two.
    bool FillIncoming() {
        if (m_deadline != 0 && GetTickCount64() >= m_deadline) {
            Log("TLS: deadline expired while reading; closing");
            m_readFailed = true;
            return false;
        }
        char buffer[8192];
        const int read = recv(m_socket, buffer, sizeof(buffer), 0);
        if (read == 0) {
            m_peerClosed = true;
            return false;
        }
        if (read == SOCKET_ERROR) {
            Log("TLS: recv failed during read (%d)", WSAGetLastError());
            m_readFailed = true;
            return false;
        }
        m_incoming.insert(m_incoming.end(), buffer, buffer + read);
        return true;
    }

    // Decrypt as much of m_incoming as forms whole records, appending to
    // m_plaintext. False means the stream ended or failed.
    bool DecryptAvailable() {
        for (;;) {
            if (m_incoming.empty()) {
                return true;
            }

            SecBuffer buffers[4];
            buffers[0].pvBuffer = m_incoming.data();
            buffers[0].cbBuffer = static_cast<unsigned long>(m_incoming.size());
            buffers[0].BufferType = SECBUFFER_DATA;
            for (int i = 1; i < 4; i++) {
                buffers[i].pvBuffer = nullptr;
                buffers[i].cbBuffer = 0;
                buffers[i].BufferType = SECBUFFER_EMPTY;
            }

            SecBufferDesc descriptor;
            descriptor.ulVersion = SECBUFFER_VERSION;
            descriptor.cBuffers = 4;
            descriptor.pBuffers = buffers;

            const SECURITY_STATUS status =
                DecryptMessage(&m_context, &descriptor, 0, nullptr);

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                // A partial record: read more and try again. Iteratively --
                // recursing here would recurse once per recv, so a peer
                // trickling a byte at a time would drive this off the stack.
                // The socket's SO_RCVTIMEO and the caller's request deadline
                // are what bound the loop.
                if (!FillIncoming()) {
                    return !m_readFailed;
                }
                continue;
            }
            if (status == SEC_I_CONTEXT_EXPIRED) {
                // The peer sent close_notify.
                m_peerClosed = true;
                m_incoming.clear();
                return true;
            }
            if (status == SEC_I_RENEGOTIATE) {
                // See the header comment: refused rather than implemented.
                Log("TLS: client asked to renegotiate; closing instead");
                m_readFailed = true;
                return false;
            }
            if (status != SEC_E_OK) {
                Log("TLS: DecryptMessage failed (0x%08lx)",
                    static_cast<unsigned long>(status));
                m_readFailed = true;
                return false;
            }

            // Collect the plaintext and carry any trailing ciphertext over.
            std::vector<char> extra;
            for (int i = 0; i < 4; i++) {
                if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                    const char* begin = static_cast<const char*>(buffers[i].pvBuffer);
                    m_plaintext.insert(m_plaintext.end(), begin,
                                       begin + buffers[i].cbBuffer);
                } else if (buffers[i].BufferType == SECBUFFER_EXTRA &&
                           buffers[i].cbBuffer > 0) {
                    const char* begin = static_cast<const char*>(buffers[i].pvBuffer);
                    extra.assign(begin, begin + buffers[i].cbBuffer);
                }
            }
            // Assigned after the loop: the SECBUFFER_EXTRA pointer points INTO
            // m_incoming, so overwriting it while still reading would be a
            // use-after-invalidation.
            m_incoming.swap(extra);

            if (!m_plaintext.empty()) {
                return true;
            }
            // A record that carried no application data (a session ticket, say)
            // -- keep going rather than returning zero bytes to the caller.
        }
    }

    bool SendRaw(const char* data, size_t length) {
        size_t sent = 0;
        while (sent < length) {
            const size_t remaining = length - sent;
            const int chunk = (remaining > 0x7FFFFFFF) ? 0x7FFFFFFF
                                                       : static_cast<int>(remaining);
            const int written = send(m_socket, data + sent, chunk, 0);
            if (written == SOCKET_ERROR || written <= 0) {
                Log("TLS: send failed after %zu/%zu bytes (%d)", sent, length,
                    WSAGetLastError());
                return false;
            }
            sent += static_cast<size_t>(written);
        }
        return true;
    }

    SOCKET m_socket;
    CtxtHandle m_context;
    // Borrowed from the process-wide ServerCredentials, which outlives every
    // channel: Shutdown needs it and the handshake is where it is available.
    CredHandle* m_credentials = nullptr;
    // 0 means no deadline. Set by Handshake, then reset by main.cpp to the
    // request deadline.
    unsigned long long m_deadline = 0;
    std::vector<char> m_incoming;   // ciphertext not yet decrypted
    std::vector<char> m_plaintext;  // decrypted bytes not yet read
    unsigned long m_headerSize = 0;
    unsigned long m_trailerSize = 0;
    size_t m_maxMessage = 0;
    bool m_peerClosed = false;
    bool m_readFailed = false;
};

}  // namespace Tls
