/*
 *  This file is part of WinSparkle (https://winsparkle.org)
 *
 *  Copyright (C) 2009-2017 Vaclav Slavik
 *  Copyright (C) 2017 Ihor Dutchak
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 */

#include "signatureverifier.h"

#include <stdexcept>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#include "error.h"
#include "settings.h"
#include "utils.h"

#define SHA_DIGEST_LENGTH 20

namespace winsparkle
{

namespace
{

class CFile
{
    FILE *f;
    CFile(const CFile &);
    CFile &operator=(const CFile &);
public:
    CFile(FILE *file): f(file) {}

    operator FILE*()
    {
        return f;
    }

    ~CFile()
    {
        if (f)
            ::fclose(f);
    }
};

class WinCryptContext
{
    HCRYPTPROV handle;

    WinCryptContext(const WinCryptContext &);
    WinCryptContext &operator=(const WinCryptContext &);

    WinCryptContext(LPCTSTR provider, DWORD prov_type)
    {
        if (!::CryptAcquireContext(&handle, NULL, provider, prov_type, CRYPT_VERIFYCONTEXT))
            throw Win32Exception("Failed to create crypto context");
    }
public:
    static WinCryptContext DSAContext()
    {
        return WinCryptContext(MS_ENH_DSS_DH_PROV, PROV_DSS_DH);
    }

    static WinCryptContext RSAContext()
    {
        return WinCryptContext(MS_ENHANCED_PROV, PROV_RSA_FULL);
    }

    ~WinCryptContext()
    {
        if (!::CryptReleaseContext(handle, 0))
            LogError("Failed to release crypto context");
    }

    operator HCRYPTPROV() const
    {
        return handle;
    }
};

class WinCryptSHA1Hash
{
    HCRYPTHASH handle;

    WinCryptSHA1Hash(const WinCryptSHA1Hash&);
    WinCryptSHA1Hash& operator=(const WinCryptSHA1Hash &);
public:
    WinCryptSHA1Hash(const WinCryptContext &ctx)
    {
        if (!::CryptCreateHash(ctx, CALG_SHA1, 0, 0, &handle))
            throw Win32Exception("Failed to create crypto hash");
    }

    ~WinCryptSHA1Hash()
    {
        if (handle)
        {
            if (!::CryptDestroyHash(handle))
            {
                LogError("Failed to destroy crypto hash");
            }
        }
    }

    operator HCRYPTHASH() const
    {
        return handle;
    }

    void hashData(const void *buffer, size_t buffer_len)
    {
        if (!::CryptHashData(handle, (const BYTE  *)buffer, buffer_len, 0))
            throw Win32Exception("Failed to hash data");
    }

    void hashFile(const std::wstring &filename)
    {
        CFile f (::_wfopen(filename.c_str(), L"rb"));
        if (!f)
            throw std::runtime_error("Failed to open file " + WideToAnsi(filename));

        const int BUF_SIZE = 8192;
        unsigned char buf[BUF_SIZE];

        while (size_t read_bytes = ::fread(buf, 1, BUF_SIZE, f))
        {
            hashData(buf, read_bytes);
        }

        if (::ferror(f))
            throw std::runtime_error("Failed to read file " + WideToAnsi(filename));
    }

    void sha1Val(unsigned char(&sha1)[SHA_DIGEST_LENGTH])
    {
        DWORD hash_len = SHA_DIGEST_LENGTH;
        if (!::CryptGetHashParam(handle, HP_HASHVAL, sha1, &hash_len, 0))
            throw Win32Exception("Failed to get SHA1 val");
    }

};

std::string CryptStrToBin(const std::string &crypt_str, DWORD flags)
{
    DWORD bin_size = 0;

    if (::CryptStringToBinaryA(&crypt_str[0], crypt_str.size(), flags, NULL, &bin_size, NULL, NULL))
    {
        std::string bin (bin_size, '\0');
        if (::CryptStringToBinaryA(&crypt_str[0], crypt_str.size(), flags, (BYTE *)&bin[0], &bin_size, NULL, NULL))
        {
            return bin;
        }
    }

    throw Win32Exception("Failed to decode string to bin");
}

std::string Base64ToBin(const std::string &base64)
{
    return CryptStrToBin(base64, CRYPT_STRING_BASE64);
}

std::string Base64HeaderToBin(const std::string &base64)
{
    return CryptStrToBin(base64, CRYPT_STRING_BASE64HEADER);
}

std::string CryptDecodeObject(const std::string &obj, LPCSTR obj_type)
{
    const BYTE *der_data = (const BYTE *)&obj[0];
    DWORD der_data_size = obj.size();

    DWORD res_size = 0;

    if (::CryptDecodeObjectEx(X509_ASN_ENCODING, obj_type, der_data, der_data_size, 0, NULL, NULL, &res_size))
    {
        std::string decoded(res_size, '\0');
        if (::CryptDecodeObjectEx(X509_ASN_ENCODING, obj_type, der_data, der_data_size, 0, NULL, &decoded[0], &res_size))
        {
            return decoded;
        }
    }

    throw "Failed to convert object";
}

// return CERT_PUBLIC_KEY_INFO data
std::string CryptDerToPubInfo(const std::string &der)
{
    try {
        return CryptDecodeObject(der, X509_PUBLIC_KEY_INFO);
    }
    catch (const char *) {
        throw Win32Exception("Failed to convert public key info");
    }
}

std::string CryptDerToDSASignature(const std::string &der)
{
    try {
        return CryptDecodeObject(der, X509_DSS_SIGNATURE);
    }
    catch (const char *) {
        throw Win32Exception("Failed to convert DSA signature");
    }
}

class WinCryptKey
{
    HCRYPTKEY handle;

    WinCryptKey(const WinCryptKey &);
    WinCryptKey &operator=(const WinCryptKey &);

    WinCryptKey(HCRYPTKEY key_handle): handle(key_handle) { }

public:
    ~WinCryptKey()
    {
        if (handle)
            if (!CryptDestroyKey(handle))
                LogError("Failed to destroy crypt key");
    }

    operator HCRYPTKEY() const
    {
        return handle;
    }

    static WinCryptKey pubFromDSAPem(const WinCryptContext &ctx, const std::string &pem)
    {
        std::string dsa_pub_der = Base64HeaderToBin(pem);
        std::string dsa_pub_data = CryptDerToPubInfo(dsa_pub_der);

        PCERT_PUBLIC_KEY_INFO dsa_pub = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(&dsa_pub_data[0]);

        HCRYPTKEY crypt_key;
        if (!CryptImportPublicKeyInfo(ctx, X509_ASN_ENCODING, dsa_pub, &crypt_key))
            throw Win32Exception("Failed to open public key");

        return WinCryptKey(crypt_key);
    }

    static WinCryptKey pubFromDSAPem(const WinCryptContext &ctx)
    {
        return pubFromDSAPem(ctx, Settings::GetDSAPubKeyPem());
    }
};

void VerifyDSASHA1Signature(const std::wstring &filename, const std::string &der_signature)
{
    unsigned char sha1[SHA_DIGEST_LENGTH];

    const WinCryptContext &ctx (WinCryptContext::DSAContext());

    // SHA1 of file
    {
        WinCryptSHA1Hash hash(ctx);
        hash.hashFile(filename);
        hash.sha1Val(sha1);
    }
    // SHA1 of SHA1 of file
    WinCryptSHA1Hash hash(ctx);
    hash.hashData(sha1, ARRAYSIZE(sha1));

    const WinCryptKey &pub_key(WinCryptKey::pubFromDSAPem(ctx));

    std::string signature = CryptDerToDSASignature(der_signature);

    if (!CryptVerifySignature(hash, (const BYTE *)&signature[0], signature.size(), pub_key, NULL, 0))
        throw Win32Exception("DSA Signature not match!");
}

} // anonynous

void SignatureVerifier::VerifyDSAPubKeyPem(const std::string &pem)
{
    const WinCryptContext &ctx(WinCryptContext::DSAContext());
    WinCryptKey::pubFromDSAPem(ctx, pem);
}

bool SignatureVerifier::DSASHA1SignatureValid(const std::wstring &filename, const std::string &signature_base64)
{
    try
    {
        if (signature_base64.size() == 0)
            throw std::runtime_error("Missing DSA signature!");
        VerifyDSASHA1Signature(filename, Base64ToBin(signature_base64));
        return true;
    }
    CATCH_ALL_EXCEPTIONS
    return false;
}

} // namespace winsparkle
