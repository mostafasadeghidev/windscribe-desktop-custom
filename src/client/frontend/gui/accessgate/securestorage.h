#pragma once
#include <QByteArray>
namespace GateSecureStorage {
// Errors never fall back to plaintext storage.
bool read(QByteArray &data);
bool write(const QByteArray &data);
bool remove();
}
