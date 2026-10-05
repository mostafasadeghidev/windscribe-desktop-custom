#pragma once
#include <functional>
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
    bool isWithinOfflineGrace() const;
    QString username() const;
    void clearSession();
    void cancelPendingLogin();
    // Commit only after Windscribe authentication, before auto-connect.
    bool completeLogin();
    void login(const QString &username, const QString &password);
    void checkNow();
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
    };
    void post(const QString &path, const QJsonObject &body, std::function<void(const HttpResult &)> callback);
    bool openEnvelope(const QJsonValue &envelope, const QString &nonce, const QString &username, QJsonObject &payload) const;
    static void recordOk(State &state, const QJsonObject &payload);
    void scheduleNextCheck(bool failed);
    void onCheckFinished(const HttpResult &result, const QString &nonce, const QString &username);
    void revoke(LockReason reason);
    void loadState();
    bool saveState();
    static QString newNonce();
    static bool withinGrace(const State &state, qint64 now);
    QNetworkAccessManager network_;
    QTimer timer_;
    QTimer graceTimer_;
    State state_;
    State pending_;
    QString deviceId_;
    int failedChecks_ = 0;
    quint64 generation_ = 0;
    bool checkInFlight_ = false;
    bool loginInFlight_ = false;
    bool periodicChecks_ = false;
    bool storageOk_ = false;
    QString serverUrl_;
    QByteArray publicKey_;
};
