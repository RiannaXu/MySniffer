QT       += core gui
QT       += core
QT       += network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += HAVE_REMOTE
DEFINES += WPCAP

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    getAdapters.cpp \
    main.cpp \
    mainwindow.cpp \
    snifferthread.cpp

HEADERS += \
    getAdapters.h \
    mainwindow.h \
    mypcap.h \
    snifferthread.h \
    structers.h

FORMS += \
    mainwindow.ui

LIBS += -lws2_32
LIBS += E:/code/c++/sniffer/sniffer/lib/WpdPack/Lib/x64/wpcap.lib
LIBS += E:/code/c++/sniffer/sniffer/lib/WpdPack/Lib/x64/packet.lib

INCLUDEPATH += $$PWD/.
INCLUDEPATH += E:\code\c++\sniffer\sniffer\lib\WpdPack\Include

DEPENDPATH += $$PWD/.

RESOURCES += \
    res/resource.qrc

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
