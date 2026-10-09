#include <QtTest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QSharedPointer>
#include <openssl/evp.h>
#include "../accessgate.h"
#include "../accessgateconfig.h"
#include "../securestorage.h"

namespace {
QByteArray saved;
bool failRead = false;
bool failWrite = false;
}
bool GateSecureStorage::read(QByteArray &data) { data = saved; return !failRead; }
bool GateSecureStorage::write(const QByteArray &data) { if (failWrite) return false; saved = data; return true; }
bool GateSecureStorage::remove() { saved.clear(); return true; }

class AccessGateTest : public QObject
{
    Q_OBJECT
    EVP_PKEY *key_ = nullptr;
    QByteArray publicKey_;
    QTcpServer server_;
    int delay_ = 0;
    int responseCode_ = 200;
    bool wrongNonce_ = false;
    QJsonObject lastRequest_;

    void configure(AccessGate &gate)
    {
        gate.publicKey_ = publicKey_;
        gate.serverUrl_ = QString("http://127.0.0.1:%1").arg(server_.serverPort());
    }
    QJsonObject payload(const AccessGate &gate, const QString &status = "active")
    {
        return {{"v", 1}, {"type", "status"}, {"username", "ali"}, {"device_id", gate.deviceId_},
                {"nonce", "nonce"}, {"status", status}, {"server_time", 1790000000000LL},
                {"check_interval_sec", 3600}, {"offline_grace_sec", 172800}};
    }
    QJsonObject sign(const QJsonObject &p)
    {
        QByteArray encoded = QJsonDocument(p).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key_);
        QByteArray sig(64, '\0'); size_t size = sig.size();
        EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(sig.data()), &size,
                       reinterpret_cast<const unsigned char *>(encoded.constData()), encoded.size());
        EVP_MD_CTX_free(ctx);
        return {{"payload", QString::fromLatin1(encoded)}, {"sig", QString::fromLatin1(sig.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))}};
    }
    void session(AccessGate &gate)
    {
        configure(gate);
        gate.state_.username = "ali";
        gate.state_.token = "token";
        AccessGate::recordOk(gate.state_, payload(gate));
        QVERIFY(gate.saveState());
    }
    AccessGate::HttpResult response(const QJsonObject &envelope)
    {
        return {200, QJsonDocument(QJsonObject{{"status", envelope}}).toJson(QJsonDocument::Compact), false};
    }

private slots:
    void initTestCase()
    {
        QByteArray seed(32, 'T'); // Test-only key; never uses the project's signing secret.
        key_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
        QVERIFY(key_);
        publicKey_.resize(32); size_t size = publicKey_.size();
        QVERIFY(EVP_PKEY_get_raw_public_key(key_, reinterpret_cast<unsigned char *>(publicKey_.data()), &size) == 1);
        QVERIFY(server_.listen(QHostAddress::LocalHost));
        connect(&server_, &QTcpServer::newConnection, this, [this] {
            auto socket = server_.nextPendingConnection();
            auto buffer = QSharedPointer<QByteArray>::create();
            connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            connect(socket, &QTcpSocket::readyRead, this, [this, socket, buffer] {
                *buffer += socket->readAll();
                int split = buffer->indexOf("\r\n\r\n");
                if (split < 0) return;
                const auto headers = buffer->left(split).split('\n');
                int length = 0;
                for (const auto &header : headers) if (header.toLower().startsWith("content-length:")) length = header.mid(15).trimmed().toInt();
                if (buffer->size() < split + 4 + length || socket->property("replied").toBool()) return;
                socket->setProperty("replied", true);
                lastRequest_ = QJsonDocument::fromJson(buffer->mid(split + 4, length)).object();
                QJsonObject p {{"v", 1}, {"type", "status"}, {"username", lastRequest_["username"]},
                    {"device_id", lastRequest_["device_id"]}, {"nonce", wrongNonce_ ? QJsonValue("wrong") : lastRequest_["nonce"]},
                    {"status", "active"}, {"server_time", 1790000000000LL}, {"check_interval_sec", 3600}, {"offline_grace_sec", 172800}};
                auto body = QJsonDocument(QJsonObject{{"token", "gate-token"}, {"status", sign(p)},
                    {"windscribe", QJsonObject{{"username", "shared-user"}, {"password", "shared-password"}}},
                    {"error", "device_limit"}}).toJson(QJsonDocument::Compact);
                auto raw = QByteArray("HTTP/1.1 ") + QByteArray::number(responseCode_) + " Test\r\nContent-Type: application/json\r\nContent-Length: " +
                    QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                QTimer::singleShot(delay_, socket, [socket, raw] { socket->write(raw); socket->disconnectFromHost(); });
            });
        });
    }
    void cleanupTestCase() { server_.close(); EVP_PKEY_free(key_); }
    void init() { saved.clear(); failRead = false; failWrite = false; delay_ = 0; responseCode_ = 200; wrongNonce_ = false; lastRequest_ = {}; }

    void validEnvelope()
    {
        AccessGate gate; configure(gate); QJsonObject opened;
        QVERIFY(gate.openEnvelope(sign(payload(gate)), "nonce", "ali", opened));
        QCOMPARE(opened["status"], QJsonValue("active"));
    }
    void wrongBinding_data()
    {
        QTest::addColumn<QString>("field"); QTest::addColumn<QJsonValue>("value");
        QTest::newRow("nonce") << QString("nonce") << QJsonValue("other");
        QTest::newRow("username") << QString("username") << QJsonValue("other");
        QTest::newRow("device") << QString("device_id") << QJsonValue("other");
        QTest::newRow("type") << QString("type") << QJsonValue("login");
        QTest::newRow("version") << QString("v") << QJsonValue(2);
        QTest::newRow("status") << QString("status") << QJsonValue("unrecognized");
        QTest::newRow("interval") << QString("check_interval_sec") << QJsonValue(-1);
        QTest::newRow("grace") << QString("offline_grace_sec") << QJsonValue(0);
    }
    void wrongBinding()
    {
        QFETCH(QString, field); QFETCH(QJsonValue, value);
        AccessGate gate; configure(gate); auto p = payload(gate); p[field] = value; QJsonObject opened;
        QVERIFY(!gate.openEnvelope(sign(p), "nonce", "ali", opened));
    }
    void tamperedEnvelope()
    {
        AccessGate gate; configure(gate); auto e = sign(payload(gate)); e["payload"] = "e30"; QJsonObject opened;
        QVERIFY(!gate.openEnvelope(e, "nonce", "ali", opened));
    }
    void loginIsStagedUntilVpnSuccess()
    {
        AccessGate gate; configure(gate); QSignalSpy success(&gate, &AccessGate::loginSucceeded);
        gate.login(" ALI ", "employee-password");
        QTRY_COMPARE(success.count(), 1);
        QVERIFY(gate.hasPendingLogin()); QVERIFY(!gate.hasSession());
        QCOMPARE(lastRequest_["username"], QJsonValue("ali"));
        QCOMPARE(QJsonDocument::fromJson(saved).object()["token"], QJsonValue(""));
        QVERIFY(!saved.contains("shared-password")); QVERIFY(!saved.contains("employee-password"));
        QVERIFY(gate.completeLogin()); QVERIFY(gate.hasSession()); QVERIFY(!gate.hasPendingLogin());
        AccessGate restarted; QCOMPARE(restarted.deviceId_, gate.deviceId_); QVERIFY(restarted.hasSession());
        gate.clearSession(); AccessGate loggedOut;
        QVERIFY(!loggedOut.hasSession()); QCOMPARE(loggedOut.deviceId_, gate.deviceId_); QCOMPARE(loggedOut.username(), QString("ali"));
    }
    void cancelDropsLateLoginResponse()
    {
        AccessGate gate; configure(gate); delay_ = 100;
        QSignalSpy success(&gate, &AccessGate::loginSucceeded);
        gate.login("ali", "password"); QTRY_VERIFY(!lastRequest_.isEmpty());
        gate.cancelPendingLogin(); QTest::qWait(180);
        QCOMPARE(success.count(), 0); QVERIFY(!gate.hasPendingLogin()); QVERIFY(!gate.hasSession());
    }
    void invalidLoginResponseIsRejected()
    {
        AccessGate gate; configure(gate); wrongNonce_ = true;
        QSignalSpy failure(&gate, &AccessGate::loginFailed);
        gate.login("ali", "password"); QTRY_COMPARE(failure.count(), 1);
        QVERIFY(!gate.hasPendingLogin()); QVERIFY(!gate.hasSession());
    }
    void logoutDropsLateCheckResponse()
    {
        AccessGate gate; session(gate); delay_ = 100;
        gate.startPeriodicChecks(); QTRY_VERIFY(!lastRequest_.isEmpty());
        gate.clearSession(); QTest::qWait(180);
        QVERIFY(!gate.hasSession()); QVERIFY(!gate.periodicChecks_);
        QCOMPARE(QJsonDocument::fromJson(saved).object()["token"], QJsonValue(""));
    }
    void deviceLimitMessage()
    {
        AccessGate gate; configure(gate); responseCode_ = 403;
        QSignalSpy failure(&gate, &AccessGate::loginFailed);
        gate.login("ali", "password"); QTRY_COMPARE(failure.count(), 1);
        QVERIFY(failure[0][0].toString().contains("another device"));
    }
    void oldSessionSurvivesRestart()
    {
        // A laptop left closed for a month must come back signed in, without a new Windscribe login.
        AccessGate gate; session(gate);
        gate.state_.lastOkLocalMs -= 30LL * 86400 * 1000; gate.state_.lastOkServerMs -= 30LL * 86400 * 1000;
        QVERIFY(gate.saveState());
        AccessGate restarted; configure(restarted);
        QVERIFY(restarted.hasSession()); QVERIFY(restarted.completeLogin());
        QCOMPARE(restarted.state_.unreachableMs, 0LL); QVERIFY(!restarted.unreachable_);
    }
    void unreachableChecksNeverSignOutBeforeLimit()
    {
        AccessGate gate; session(gate); gate.periodicChecks_ = true;
        QSignalSpy revoked(&gate, &AccessGate::accessRevoked);
        for (int i = 0; i < 10; ++i) gate.onCheckFinished({0, {}, true}, "nonce", "ali");
        QCOMPARE(revoked.count(), 0); QVERIFY(gate.hasSession()); QVERIFY(gate.unreachable_);
        QVERIFY(QJsonDocument::fromJson(saved).object().contains("unreachable_ms"));
    }
    void unreachableLimitSignsOut()
    {
        AccessGate gate; session(gate); gate.periodicChecks_ = true;
        QSignalSpy revoked(&gate, &AccessGate::accessRevoked);
        gate.unreachable_ = true; gate.state_.unreachableMs = AccessGateConfig::kMaxUnreachableMs - 1;
        gate.onCheckFinished({0, {}, true}, "nonce", "ali");
        QCOMPARE(revoked.count(), 0); QVERIFY(gate.hasSession());
        gate.state_.unreachableMs = AccessGateConfig::kMaxUnreachableMs;
        gate.onCheckFinished({0, {}, true}, "nonce", "ali");
        QCOMPARE(revoked.count(), 1); QVERIFY(!gate.hasSession());
        QCOMPARE(revoked[0][0].value<AccessGate::LockReason>(), AccessGate::LockReason::kOfflineTooLong);
    }
    void validAnswerResetsUnreachableTime()
    {
        AccessGate gate; session(gate); gate.periodicChecks_ = true;
        gate.unreachable_ = true; gate.state_.unreachableMs = 3LL * 86400 * 1000;
        gate.onCheckFinished(response(sign(payload(gate))), "nonce", "ali");
        QVERIFY(!gate.unreachable_); QCOMPARE(gate.state_.unreachableMs, 0LL);
        QCOMPARE(QJsonDocument::fromJson(saved).object()["unreachable_ms"].toInteger(), 0LL);
    }
    void unreachableTimePersistsAcrossRestart()
    {
        AccessGate gate; session(gate);
        gate.unreachable_ = true; gate.state_.unreachableMs = 123456; QVERIFY(gate.saveState());
        AccessGate restarted;
        QCOMPARE(restarted.state_.unreachableMs, 123456LL); QVERIFY(restarted.unreachable_);
    }
    void unreachableTimeOnlyGrowsWhileUnreachable()
    {
        AccessGate gate; session(gate);
        gate.accumulateUnreachable(); QTest::qWait(30); gate.accumulateUnreachable();
        QCOMPARE(gate.state_.unreachableMs, 0LL);
        gate.unreachable_ = true;
        gate.accumulateUnreachable(); QTest::qWait(30); gate.accumulateUnreachable();
        QVERIFY(gate.state_.unreachableMs > 0);
        QVERIFY(gate.state_.unreachableMs <= AccessGateConfig::kUnreachableMaxStepMs);
    }
    void recheckSupersedesCheckInFlight()
    {
        AccessGate gate; session(gate); gate.periodicChecks_ = true; delay_ = 150;
        gate.checkNow(); QTRY_VERIFY(!lastRequest_.isEmpty());
        const auto firstSeq = gate.checkSeq_;
        gate.recheckNow();
        // One step discards the reply in flight, one numbers the fresh request.
        QCOMPARE(gate.checkSeq_, firstSeq + 2); QVERIFY(gate.checkInFlight_);
        QTRY_VERIFY_WITH_TIMEOUT(!gate.checkInFlight_, 3000);
        QVERIFY(gate.hasSession()); QVERIFY(!gate.unreachable_); QCOMPARE(gate.failedChecks_, 0);
    }
    void invalidCheckKeepsSessionAndBacksOff()
    {
        AccessGate gate; session(gate); gate.periodicChecks_ = true;
        const auto oldTime = gate.state_.lastOkLocalMs;
        for (int seconds : {60, 300, 900, 3600}) {
            gate.onCheckFinished({200, "{}", false}, "nonce", "ali");
            QVERIFY(gate.hasSession()); QCOMPARE(gate.state_.lastOkLocalMs, oldTime);
            QVERIFY(qAbs(gate.timer_.remainingTime() - seconds * 1000) < 1000);
        }
        gate.onCheckFinished(response(sign(payload(gate))), "nonce", "ali");
        QCOMPARE(gate.failedChecks_, 0);
    }
    void revokeStatus_data()
    {
        QTest::addColumn<QString>("status");
        QTest::newRow("disabled") << QString("disabled");
        QTest::newRow("device_revoked") << QString("device_revoked");
        QTest::newRow("unknown_user") << QString("unknown_user");
    }
    void revokeStatus()
    {
        QFETCH(QString, status); AccessGate gate; session(gate);
        QSignalSpy revoked(&gate, &AccessGate::accessRevoked);
        gate.onCheckFinished(response(sign(payload(gate, status))), "nonce", "ali");
        QCOMPARE(revoked.count(), 1); QVERIFY(!gate.hasSession());
        QCOMPARE(QJsonDocument::fromJson(saved).object()["token"], QJsonValue(""));
    }
    void staleSessionIsRevivedByValidAnswer()
    {
        AccessGate gate; session(gate); gate.state_.lastOkLocalMs -= 30LL * 86400 * 1000;
        QSignalSpy revoked(&gate, &AccessGate::accessRevoked);
        gate.onCheckFinished(response(sign(payload(gate))), "nonce", "ali");
        QCOMPARE(revoked.count(), 0); QVERIFY(gate.hasSession());
        QVERIFY(qAbs(gate.state_.lastOkLocalMs - QDateTime::currentMSecsSinceEpoch()) < 5000);
    }
    void storageFailureLocksInsteadOfPersistingPlaintext()
    {
        AccessGate gate; configure(gate);
        gate.pending_.username = "ali"; gate.pending_.token = "pending-token";
        AccessGate::recordOk(gate.pending_, payload(gate)); failWrite = true;
        QSignalSpy revoked(&gate, &AccessGate::accessRevoked);
        QVERIFY(!gate.completeLogin()); QCOMPARE(revoked.count(), 1);
        QVERIFY(!gate.hasSession()); QVERIFY(!gate.hasPendingLogin()); QVERIFY(saved.isEmpty());
    }
    void unavailableStorageRejectsLogin()
    {
        failRead = true; AccessGate gate; configure(gate);
        QSignalSpy failed(&gate, &AccessGate::loginFailed);
        gate.login("ali", "password"); QCOMPARE(failed.count(), 1); QVERIFY(!gate.hasPendingLogin());
    }
};
QTEST_GUILESS_MAIN(AccessGateTest)
#include "accessgate_test.moc"
