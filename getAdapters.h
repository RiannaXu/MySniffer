#ifndef GETADAPTERS_H
#define GETADAPTERS_H
#define IPTOSBUFFERS 12

#include "mypcap.h"
#include "structers.h"

#include <QDebug>

using namespace std;

vector<NetworkAdapter> getNetworkAdapters();

#endif // UTILS_H
