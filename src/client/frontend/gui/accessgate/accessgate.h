#pragma once
#include <functional>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QTimer>

class AccessGate : public QObject
{
    Q_OBJECT
public:
    enum class LockReason { kDisabled, kDeviceRevoked, kUnknownUser, kOfflineTooLong, kStorageError };
    Q_ENUM(LockReason)
    explicit AccessGate(QObject *parent = nullptr);
    bool hasSession() const;
    bool hasPendingLogin() const;
    QString username() const;
    void clearSession();
    void cancelPendingLogin();
    // Commit only after Windscribe authentication, before auto-connect.
    bool completeLogin();
    void login(const QString &username, const QString &password);
    void checkNow();
    // Check again now, discarding any check still in flight. Call once the VPN tunnel is up so a check
    // that could not reach the server on the open network is repeated through the tunnel.
    void recheckNow();
    void startPeriodicChecks();
    void stopPeriodicChecks();
    static QString lockMessage(LockReason reason);
signals:
    void loginSucceeded(const QString &windscribeUsername, const QString &windscribePassword);
    void loginFailed(const QString &message);
    void accessRevoked(AccessGate::LockReason reason);
private:
    friend class AccessGateTest;
    struct HttpResult { int status = 0; QByteArray body; bool networkError = false; };
    struct State {
        QString username;
        QString token;
        qint64 lastOkLocalMs = 0;
        qint64 lastOkServerMs = 0;
        int checkIntervalSec = 3600;
        int offlineGraceSec = 172800;
        // App running time since the last valid answer, counted only while checks are failing.
        qint64 unreachableMs = 0;
    };
    void post(const QString &path, const QJsonObject &body, std::function<void(const HttpResult &)> callback);
    bool openEnvelope(const QJsonValue &envelope, const QString &nonce, const QString &username, QJsonObject &payload) const;
    static void recordOk(State &state, const QJsonObject &payload);
    void scheduleNextCheck(bool failed);
    void onCheckFinished(const HttpResult &result, const QString &nonce, const QString &username);
    void revoke(LockReason reason);
    void loadState();
    bool saveState();
    void accumulateUnreachable();
    static QString newNonce();
    QNetworkAccessManager network_;
    QTimer timer_;
    QTimer unreachableTimer_;
    QElapsedTimer unreachableClock_;
    int unreachableTicks_ = 0;
    bool unreachable_ = false;
    State state_;
    State pending_;
    QString deviceId_;
    int failedChecks_ = 0;
    quint64 generation_ = 0;
    quint64 checkSeq_ = 0;
    bool checkInFlight_ = false;
    bool loginInFlight_ = false;
    bool periodicChecks_ = false;
    bool storageOk_ = false;
    QString serverUrl_;
    QByteArray publicKey_;
};
