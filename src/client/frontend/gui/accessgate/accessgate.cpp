#include "accessgate.h"
#include <algorithm>
#include <QCoreApplication>
#include <QDateTime>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QRandomGenerator>
#include <QSysInfo>
#include <QUuid>
#include <openssl/evp.h>
#include "accessgateconfig.h"
#include "securestorage.h"

namespace {
QByteArray fromBase64Url(const QString &s)
{
    return QByteArray::fromBase64(s.toLatin1(), QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
}
bool verifyEd25519(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature)
{
    if (publicKey.size() != 32 || signature.size() != 64) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(publicKey.constData()), publicKey.size());
    if (!key) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(signature.constData()), signature.size(),
                        reinterpret_cast<const unsigned char *>(message.constData()), message.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}
QString platformName()
{
#if defined(Q_OS_WIN)
    return "windows";
#elif defined(Q_OS_MACOS)
    return "macos";
#else
    return "linux";
#endif
}
}

AccessGate::AccessGate(QObject *parent) : QObject(parent), network_(this)
{
    serverUrl_ = QString::fromLatin1(AccessGateConfig::kServerUrl);
    publicKey_ = QByteArray::fromBase64(AccessGateConfig::kPublicKeyBase64);
    loadState();
    timer_.setSingleShot(true);
    connect(&timer_, &QTimer::timeout, this, &AccessGate::checkNow);
    // Enforce grace while a request hangs, during 2FA, and on backwards clock jumps.
    graceTimer_.setInterval(1000);
    connect(&graceTimer_, &QTimer::timeout, this, [this] {
        if ((hasSession() || hasPendingLogin()) && !isWithinOfflineGrace()) revoke(LockReason::kOfflineTooLong);
    });
}
bool AccessGate::hasSession() const { return !state_.token.isEmpty(); }
bool AccessGate::hasPendingLogin() const { return !pending_.token.isEmpty(); }
QString AccessGate::username() const { return state_.username; }
bool AccessGate::withinGrace(const State &state, qint64 now)
{
    return !state.token.isEmpty() && state.lastOkLocalMs > 0 && state.offlineGraceSec > 0 &&
        now >= state.lastOkLocalMs - AccessGateConfig::kClockSkewToleranceMs &&
        now - state.lastOkLocalMs <= static_cast<qint64>(state.offlineGraceSec) * 1000;
}
bool AccessGate::isWithinOfflineGrace() const
{
    return withinGrace(hasPendingLogin() ? pending_ : state_, QDateTime::currentMSecsSinceEpoch());
}
void AccessGate::cancelPendingLogin()
{
    ++generation_;
    pending_ = State();
    loginInFlight_ = false;
    checkInFlight_ = false;
    if (!hasSession()) graceTimer_.stop();
}
void AccessGate::clearSession()
{
    stopPeriodicChecks();
    cancelPendingLogin();
    const QString user = state_.username;
    state_ = State();
    state_.username = user;
    if (!saveState()) { storageOk_ = false; GateSecureStorage::remove(); }
}
bool AccessGate::completeLogin()
{
    if (!isWithinOfflineGrace()) { revoke(LockReason::kOfflineTooLong); return false; }
    if (hasPendingLogin()) {
        state_ = pending_;
        pending_ = State();
        if (!saveState()) { revoke(LockReason::kStorageError); return false; }
    }
    return hasSession();
}
void AccessGate::login(const QString &username, const QString &password)
{
    if (loginInFlight_) return;
    cancelPendingLogin();
    if (!storageOk_ || deviceId_.isEmpty()) { emit loginFailed(lockMessage(LockReason::kStorageError)); return; }
    graceTimer_.start();
    loginInFlight_ = true;
    const QString user = username.trimmed().toLower();
    const QString nonce = newNonce();
    const QJsonObject body {
        {"username", user}, {"password", password}, {"device_id", deviceId_},
        {"device_name", QSysInfo::machineHostName()}, {"platform", platformName()},
        {"app_version", QCoreApplication::applicationVersion()}, {"nonce", nonce}
    };
    post("/api/v1/login", body, [this, nonce, user](const HttpResult &result) {
        loginInFlight_ = false;
        const auto obj = QJsonDocument::fromJson(result.body).object();
        if (result.status != 200) {
            const QString error = obj.value("error").toString();
            QString message = tr("Cannot reach the access server. Check your internet connection.");
            if (error == "invalid_credentials") message = tr("Incorrect employee username or password.");
            else if (error == "disabled") message = lockMessage(LockReason::kDisabled);
            else if (error == "device_limit") message = tr("This account is active on another device. Contact your administrator.");
            else if (error == "too_many_attempts") message = tr("Too many attempts. Please try again in 15 minutes.");
            emit loginFailed(message);
            return;
        }
        QJsonObject payload;
        const auto ws = obj.value("windscribe").toObject();
        const QString token = obj.value("token").toString();
        if (result.networkError || !openEnvelope(obj.value("status"), nonce, user, payload) ||
            payload.value("status") != "active" || token.isEmpty() || token.size() > 128 ||
            ws.value("username").toString().isEmpty() || ws.value("password").toString().isEmpty()) {
            emit loginFailed(tr("Invalid response from the access server."));
            return;
        }
        pending_ = State();
        pending_.username = user;
        pending_.token = token;
        recordOk(pending_, payload);
        emit loginSucceeded(ws.value("username").toString(), ws.value("password").toString());
    });
}
void AccessGate::post(const QString &path, const QJsonObject &body, std::function<void(const HttpResult &)> callback)
{
    QNetworkRequest request{QUrl(serverUrl_ + path)};
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setTransferTimeout(20000);
    auto reply = network_.post(request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    reply->setReadBufferSize(64 * 1024 + 1);
    connect(reply, &QIODevice::readyRead, reply, [reply] {
        if (reply->bytesAvailable() > 64 * 1024) reply->abort();
    });
    // Total deadline also covers trickling responses.
    QTimer::singleShot(20000, reply, [reply] { if (!reply->isFinished()) reply->abort(); });
    const auto generation = generation_;
    connect(reply, &QNetworkReply::finished, this, [this, reply, callback, generation] {
        HttpResult result;
        result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        result.networkError = reply->error() != QNetworkReply::NoError && (result.status == 0 || result.status == 200);
        result.body = reply->readAll();
        reply->deleteLater();
        if (generation == generation_) callback(result);
    });
}
bool AccessGate::openEnvelope(const QJsonValue &envelope, const QString &nonce, const QString &username, QJsonObject &payload) const
{
    const auto obj = envelope.toObject();
    const QString encoded = obj.value("payload").toString();
    if (encoded.isEmpty() || !verifyEd25519(publicKey_, encoded.toUtf8(),
                                           fromBase64Url(obj.value("sig").toString()))) return false;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(fromBase64Url(encoded), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
    payload = doc.object();
    const auto interval = payload.value("check_interval_sec").toDouble();
    const auto grace = payload.value("offline_grace_sec").toDouble();
    const QString status = payload.value("status").toString();
    return payload.value("v") == 1 && payload.value("type") == "status" &&
        payload.value("nonce") == nonce && payload.value("username") == username && payload.value("device_id") == deviceId_ &&
        (status == "active" || status == "disabled" || status == "device_revoked" || status == "unknown_user") &&
        payload.value("server_time").toDouble() > 0 &&
        interval >= 1 && interval <= 86400 && interval == static_cast<int>(interval) &&
        grace >= 1 && grace <= 30 * 86400 && grace == static_cast<int>(grace);
}
void AccessGate::recordOk(State &state, const QJsonObject &payload)
{
    state.lastOkLocalMs = QDateTime::currentMSecsSinceEpoch();
    state.lastOkServerMs = payload.value("server_time").toInteger();
    state.checkIntervalSec = payload.value("check_interval_sec").toInt();
    state.offlineGraceSec = payload.value("offline_grace_sec").toInt();
}
void AccessGate::checkNow()
{
    if (!hasSession()) return;
    if (!isWithinOfflineGrace()) { revoke(LockReason::kOfflineTooLong); return; }
    if (checkInFlight_) return;
    checkInFlight_ = true;
    const QString nonce = newNonce();
    const QString user = state_.username;
    const QJsonObject body {
        {"username", user}, {"device_id", deviceId_}, {"token", state_.token}, {"nonce", nonce},
        {"app_version", QCoreApplication::applicationVersion()}
    };
    post("/api/v1/check", body, [this, nonce, user](const HttpResult &result) { onCheckFinished(result, nonce, user); });
}
void AccessGate::onCheckFinished(const HttpResult &result, const QString &nonce, const QString &username)
{
    checkInFlight_ = false;
    if (!isWithinOfflineGrace()) { revoke(LockReason::kOfflineTooLong); return; }
    QJsonObject payload;
    if (result.networkError || result.status != 200 ||
        !openEnvelope(QJsonDocument::fromJson(result.body).object().value("status"), nonce, username, payload)) {
        if (!isWithinOfflineGrace()) revoke(LockReason::kOfflineTooLong);
        else scheduleNextCheck(true);
        return;
    }
    const auto status = payload.value("status").toString();
    if (status != "active") {
        revoke(status == "disabled" ? LockReason::kDisabled : status == "device_revoked" ? LockReason::kDeviceRevoked : LockReason::kUnknownUser);
        return;
    }
    recordOk(state_, payload);
    if (!saveState()) { revoke(LockReason::kStorageError); return; }
    scheduleNextCheck(false);
}
void AccessGate::scheduleNextCheck(bool failed)
{
    if (!periodicChecks_ || !hasSession()) return;
    int seconds = state_.checkIntervalSec;
    if (failed) {
        if (failedChecks_ < 3) seconds = AccessGateConfig::kRetryDelaysSec[failedChecks_];
        failedChecks_ = std::min(failedChecks_ + 1, 3);
    } else failedChecks_ = 0;
    timer_.start(seconds * 1000);
}
void AccessGate::startPeriodicChecks()
{
    if (periodicChecks_) return;
    periodicChecks_ = true;
    graceTimer_.start();
    failedChecks_ = 0;
    checkNow();
}
void AccessGate::stopPeriodicChecks() { periodicChecks_ = false; timer_.stop(); graceTimer_.stop(); }
void AccessGate::revoke(LockReason reason) { clearSession(); emit accessRevoked(reason); }
QString AccessGate::newNonce()
{
    QByteArray bytes(16, '\0');
    for (auto &b : bytes) b = static_cast<char>(QRandomGenerator::system()->generate() & 0xff);
    return QString::fromLatin1(bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}
QString AccessGate::lockMessage(LockReason reason)
{
    if (reason == LockReason::kOfflineTooLong) return tr("Cannot reach the access server. Please sign in again.");
    if (reason == LockReason::kStorageError) return tr("Secure storage is unavailable. Unlock your system keyring and restart the app.");
    return tr("Your access has been disabled. Contact your administrator.");
}
void AccessGate::loadState()
{
    QByteArray bytes;
    storageOk_ = GateSecureStorage::read(bytes);
    if (!storageOk_) return;
    if (!bytes.isEmpty()) {
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(bytes, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject() || doc.object().value("v") != 1) { storageOk_ = false; return; }
        const auto obj = doc.object();
        deviceId_ = obj.value("device_id").toString();
        if (QUuid(deviceId_).isNull()) { storageOk_ = false; return; }
        state_.username = obj.value("username").toString();
        state_.token = obj.value("token").toString();
        state_.lastOkLocalMs = obj.value("last_ok_local_time").toInteger();
        state_.lastOkServerMs = obj.value("last_ok_server_time").toInteger();
        state_.checkIntervalSec = obj.value("check_interval_sec").toInt(3600);
        state_.offlineGraceSec = obj.value("offline_grace_sec").toInt(172800);
        if (state_.checkIntervalSec < 1 || state_.checkIntervalSec > 86400 || state_.offlineGraceSec < 1 || state_.offlineGraceSec > 30 * 86400) state_.token.clear();
    } else {
        deviceId_ = QUuid::createUuid().toString(QUuid::WithoutBraces);
        storageOk_ = saveState();
    }
}
bool AccessGate::saveState()
{
    const QJsonObject obj {
        {"v", 1}, {"device_id", deviceId_}, {"username", state_.username}, {"token", state_.token},
        {"last_ok_local_time", state_.lastOkLocalMs}, {"last_ok_server_time", state_.lastOkServerMs},
        {"check_interval_sec", state_.checkIntervalSec}, {"offline_grace_sec", state_.offlineGraceSec}
    };
    return GateSecureStorage::write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}
