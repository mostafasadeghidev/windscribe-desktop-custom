#include "../securestorage.h"
#include <QCoreApplication>
#include <QFile>
#include <QSettings>
#include <QSslSocket>
#include <QTemporaryDir>
#include <QtTest>

class SecureStorageWindowsTest : public QObject
{
    Q_OBJECT
private slots:
    void tlsBackendAvailable()
    {
        QVERIFY(QSslSocket::supportsSsl());
    }

    void dpapiRoundTrip()
    {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, temporary.path());
        QCoreApplication::setOrganizationName("EmployeeGateTest");
        QCoreApplication::setApplicationName("IsolatedSecureStorage");

        QByteArray result;
        QVERIFY(GateSecureStorage::read(result));
        QVERIFY(result.isEmpty());
        const QByteArray identity = QByteArray("test identity: ") + QByteArray::fromHex("daa9d8a7d8b1d985d986d8af");
        QVERIFY(GateSecureStorage::write(identity));
        QVERIFY(GateSecureStorage::read(result));
        QCOMPARE(result, identity);
        QSettings settings;
        QFile file(settings.fileName());
        QVERIFY(file.open(QIODevice::ReadOnly));
        QVERIFY(!file.readAll().contains(identity));
        file.close();

        settings.setValue("AccessGate/secureIdentity", QByteArray("invalid-ciphertext"));
        settings.sync();
        QVERIFY(!GateSecureStorage::read(result));
        QVERIFY(result.isEmpty());
        QVERIFY(GateSecureStorage::remove());
        QVERIFY(GateSecureStorage::read(result));
        QVERIFY(result.isEmpty());
    }
};

QTEST_GUILESS_MAIN(SecureStorageWindowsTest)
#include "securestorage_windows_test.moc"
