#include "securestorage.h"
#include <QtGlobal>
#include <QSettings>
#if defined(Q_OS_WIN)
#include "utils/wincryptutils.h"
#elif defined(Q_OS_MACOS)
#include <Security/Security.h>
#elif defined(Q_OS_LINUX)
#pragma push_macro("signals")
#undef signals
#include <libsecret/secret.h>
#pragma pop_macro("signals")
#endif

namespace {
#if defined(Q_OS_MACOS)
CFMutableDictionaryRef query()
{
    auto q = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, CFSTR("com.windscribe.employee-gate"));
    CFDictionarySetValue(q, kSecAttrAccount, CFSTR("identity"));
    return q;
}
#elif defined(Q_OS_LINUX)
const SecretSchema schema = {
    "com.windscribe.employee-gate", SECRET_SCHEMA_NONE,
    { {"account", SECRET_SCHEMA_ATTRIBUTE_STRING}, {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING} },
    0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
};
#endif
}

bool GateSecureStorage::read(QByteArray &data)
{
    data.clear();
#if defined(Q_OS_WIN)
    try {
        const QByteArray encrypted = QSettings().value("AccessGate/secureIdentity").toByteArray();
        if (!encrypted.isEmpty()) data = QString::fromStdWString(wsl::WinCryptUtils::decrypt(encrypted.toStdString())).toUtf8();
        return true;
    } catch (...) { return false; }
#elif defined(Q_OS_MACOS)
    auto q = query();
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFTypeRef result = nullptr;
    const OSStatus status = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (status == errSecItemNotFound) return true;
    if (status != errSecSuccess) return false;
    auto bytes = static_cast<CFDataRef>(result);
    data = QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(bytes)), CFDataGetLength(bytes));
    CFRelease(result);
    return true;
#elif defined(Q_OS_LINUX)
    GError *error = nullptr;
    gchar *value = secret_password_lookup_sync(&schema, nullptr, &error, "account", "identity", nullptr);
    if (error) { g_error_free(error); return false; }
    if (value) { data = QByteArray(value); secret_password_free(value); }
    return true;
#else
    return false;
#endif
}

bool GateSecureStorage::write(const QByteArray &data)
{
#if defined(Q_OS_WIN)
    try {
        const auto encrypted = wsl::WinCryptUtils::encrypt(QString::fromUtf8(data).toStdWString());
        QSettings settings;
        settings.setValue("AccessGate/secureIdentity", QByteArray::fromStdString(encrypted));
        settings.sync();
        return settings.status() == QSettings::NoError;
    } catch (...) { return false; }
#elif defined(Q_OS_MACOS)
    auto q = query();
    auto bytes = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(data.constData()), data.size());
    auto attrs = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecValueData, bytes);
    OSStatus status = SecItemUpdate(q, attrs);
    if (status == errSecItemNotFound) {
        CFDictionarySetValue(q, kSecValueData, bytes);
        CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        status = SecItemAdd(q, nullptr);
    }
    CFRelease(attrs);
    CFRelease(bytes);
    CFRelease(q);
    return status == errSecSuccess;
#elif defined(Q_OS_LINUX)
    GError *error = nullptr;
    const bool ok = secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT, "Windscribe employee access", data.constData(),
                                               nullptr, &error, "account", "identity", nullptr);
    if (error) g_error_free(error);
    return ok;
#else
    return false;
#endif
}

bool GateSecureStorage::remove()
{
#if defined(Q_OS_WIN)
    QSettings settings;
    settings.remove("AccessGate/secureIdentity");
    settings.sync();
    return settings.status() == QSettings::NoError;
#elif defined(Q_OS_MACOS)
    auto q = query();
    const OSStatus status = SecItemDelete(q);
    CFRelease(q);
    return status == errSecSuccess || status == errSecItemNotFound;
#elif defined(Q_OS_LINUX)
    GError *error = nullptr;
    const bool ok = secret_password_clear_sync(&schema, nullptr, &error, "account", "identity", nullptr);
    if (error) g_error_free(error);
    return ok;
#else
    return false;
#endif
}
