CONFIG -= QT
QT     -= core gui

TARGET = testsch2
HEADERS += \
   ./utlist.h \
   ./uthash.h \
   ./ll_updater.h \

SOURCES += \
   ./ll_updater.c \

#--- your libs
#--- your includes
LIBS +=
linux-g++: INCLUDEPATH +=$PWD \
   $PWD/. \
