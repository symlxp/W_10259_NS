#include "selectnetworkcard.h"
#include "ui_selectnetworkcard.h"

SelectNetworkCard::SelectNetworkCard(QWidget *parent,QVector<QMap<QString, QString>> network_card_list) :
    QDialog(parent),
    ui(new Ui::SelectNetworkCard)
{
    ui->setupUi(this);

    dev_list = network_card_list;

    for(QMap<QString, QString> i :dev_list){
        ui->comboBox->addItem(i["name"]);
    }

    ui->comboBox->setCurrentIndex(0);

    getUserSelectUI(0);

    void(QComboBox::*fp)(int)=&QComboBox::currentIndexChanged;
    connect(ui->comboBox,fp,this,&SelectNetworkCard::getUserSelectUI);

}

SelectNetworkCard::~SelectNetworkCard()
{
    delete ui;
}

void SelectNetworkCard::getUserSelectUI(int x){

    user_select = ui->comboBox->currentText();

    int count=0;

    for(QMap<QString,QString> i :dev_list){
        if(count==x){
            ui->network_card_boardcast->setText(i["boardcast"]);
            ui->network_card_description->setText(i["description"]);
            ui->network_card_IP->setText(i["address"]);
            ui->network_card_netmask->setText(i["netmask"]);
            break;
        }
        count++;
    }

}
