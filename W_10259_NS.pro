#-------------------------------------------------
#
# Project created by QtCreator 2018-04-21T12:39:08
#
#-------------------------------------------------

QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = W_10259_NS
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    arpspoofing.cpp \
    getdatapackage.cpp \
    selectnetworkcard.cpp \
    universaltools.cpp \
    parsedatapackage.cpp

HEADERS += \
        mainwindow.h \
    arpspoofing.h \
    getdatapackage.h \
    selectnetworkcard.h \
    universaltools.h \
    include/pcap/bluetooth.h \
    include/pcap/bpf.h \
    include/pcap/namedb.h \
    include/pcap/pcap.h \
    include/pcap/sll.h \
    include/pcap/usb.h \
    include/pcap/vlan.h \
    include/bittypes.h \
    include/ip6_misc.h \
    include/Packet32.h \
    include/pcap-bpf.h \
    include/pcap-namedb.h \
    include/pcap-stdinc.h \
    include/pcap.h \
    include/remote-ext.h \
    include/Win32-Extensions.h \
    parsedatapackage.h

FORMS += \
        mainwindow.ui \
    selectnetworkcard.ui

LIBS += ../W_10259_NS\lib\Packet.lib
LIBS += ../W_10259_NS\lib\wpcap.lib
LIBS += -lws2_32

DISTFILES += \
    lib/Packet.lib \
    lib/wpcap.lib
