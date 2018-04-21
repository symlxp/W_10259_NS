#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <QObject>
#include <QThread>

class ARPSpoofing : public QThread
{
    Q_OBJECT

public slots:
    void startSpoofingSlot(QString);
    void stopSpoofingSlot();
};

#endif // ARPSPOOFING_H
