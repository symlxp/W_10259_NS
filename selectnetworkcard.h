#ifndef SELECTNETWORKCARD_H
#define SELECTNETWORKCARD_H

#include <QDialog>

namespace Ui {
class SelectNetworkCard;
}

class SelectNetworkCard : public QDialog
{
    Q_OBJECT

public:
    explicit SelectNetworkCard(QWidget *parent,QVector<QMap<QString, QString>> network_card_list);
    ~SelectNetworkCard();
    QString user_select;
    QVector<QMap<QString, QString>> dev_list;

private:
    Ui::SelectNetworkCard *ui;
    void getUserSelectUI(int);
};

#endif // SELECTNETWORKCARD_H
