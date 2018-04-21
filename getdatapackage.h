#ifndef GETDATAPACKAGE_H
#define GETDATAPACKAGE_H

#include <QObject>
#include <QThread>

struct PackageBrief
{
    long long package_id;
};

class GetDataPackage : public QThread
{
    Q_OBJECT


signals:
    void getDataPackage(PackageBrief);

};

#endif // GETDATAPACKAGE_H
