#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    this->setFixedSize(1142,706);
    ui->setupUi(this);

    adapters = getNetworkAdapters();

    //菜单栏
    ui->menuBar->setGeometry(0,0,this->width(),30);
    ui->menuBar->addAction("帮助");
    ui->menuBar->addAction("关于");
    connect(ui->menuBar,SIGNAL(triggered(QAction*)),this,SLOT(trigerMenu(QAction*)));

    //状态栏
    QString localHostName = QHostInfo::localHostName();
    ui->statusBar->showMessage("本机名称： " + localHostName);

    //其余组件
    initComoBox();
    initFilter();
    initTable();
    initTree();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::trigerMenu(QAction* act)
{

    if(act->text() == "帮助")
    {
        messageBoxHelp();
    }
    if(act->text() == "关于")
    {
        messageBoxMore();
    }

}


void MainWindow::messageBoxHelp(){
    QMessageBox* MyBox = new QMessageBox();
    MyBox->setParent(this);
    MyBox->setWindowFlags(Qt::Dialog);

    QPixmap pix(":help.png");
    MyBox->setIconPixmap(pix);

    MyBox->addButton("确定", QMessageBox::AcceptRole);

    MyBox->setWindowTitle("帮助");
    MyBox->setText("\n使用说明：\n\n"
                   "1.在下拉框选择网卡，点击开始抓包后开启混杂模式抓包。\n\n"
                   "2.抓包过滤器默认全部抓取，可自定义规则，符合bpf格式。\n\n"
                   "3.双击表格中数据包查看详细内容。\n");
    MyBox->exec();
}


void MainWindow::messageBoxMore()
{
    QMessageBox* MyBox = new QMessageBox();

    MyBox->setParent(this);
    MyBox->setWindowFlags(Qt::Dialog);

    QPixmap pix(":moreInfo.png");
    MyBox->setIconPixmap(pix);

    MyBox->addButton("确定", QMessageBox::AcceptRole);

    MyBox->setWindowTitle("关于");
    MyBox->setText("UCAS-SCS\n\n"
                   "网络攻防基础-Exp01-A         \n\n"
                   "Rianna's Sniffer\t\n");
    MyBox->exec();
}


void MainWindow::initComoBox(){
    string str;
    for(const NetworkAdapter& adapter : adapters){
        str = adapter.name + "：";
        str += adapter.ip_address + "(";
        str += adapter.netmask + ")";
        ui->comboBox->addItem(QString::fromStdString(str));
    }
}

void MainWindow::initTable(){

    tableData = new QStandardItemModel();

    tableData->setColumnCount(6);
    tableData->setHeaderData(0,Qt::Horizontal,"Time");
    tableData->setHeaderData(1,Qt::Horizontal,"Source");
    tableData->setHeaderData(2,Qt::Horizontal,"Destination");
    tableData->setHeaderData(3,Qt::Horizontal,"Protocol");
    tableData->setHeaderData(4,Qt::Horizontal,"Length");
    tableData->setHeaderData(5,Qt::Horizontal,"Info");

    QFont boldFont = ui->tableView->horizontalHeader()->font();
    boldFont.setBold(true);
    ui->tableView->horizontalHeader()->setFont(boldFont);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers); //不可编辑
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows); //整行选中
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableView->horizontalHeader()->setHighlightSections(true);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    ui->tableView->setModel(tableData);
//    ui->tableView->resizeColumnsToContents();
    ui->tableView->setColumnWidth(0,150);
    ui->tableView->setColumnWidth(1,180);
    ui->tableView->setColumnWidth(2,180);
    ui->tableView->setColumnWidth(3,85);
    ui->tableView->setColumnWidth(4,130);
    ui->tableView->horizontalHeader()->setStretchLastSection(true);
}

void MainWindow::initTree(){
    treeData = new QStandardItemModel();
    ui->treeView->header()->hide();
    ui->treeView->setModel(treeData);
}

void MainWindow::initFilter(){
    ui->filterText->setText("default");
}


void MainWindow::on_startButton_clicked(bool checked)
{
    if(!checked){
        //这里有个bug，如果一个包都没抓到就停止线程，会报错QThread: Destroyed while thread is still running
        //这个bug好像解决了，在线程的类中添加了requestInterruption();并且在下方退出时使用quit()调用析取函数
        //不知道现在正常抓包还会不会程序一场推出，无语
        //现在好像真的解决了（2023.10.20）
        if(catchPacketThread->isRunning()){
            catchPacketThread->quit();
            //catchPacketThread->wait(100);
            delete catchPacketThread;
            catchPacketThread = nullptr;
        }
        qDebug()<<"停止抓包";
        ui->startButton->setText("开始抓包");
    }else{
        packetVector.clear();
        packetRaw.clear();
        initTable();
        treeData->clear();
        ui->rawTextEdit->clear();

        int num = ui->comboBox->currentIndex();
        string interface_name = adapters[num].name;
        QString filter = ui->filterText->text();
        catchPacketThread = new SnifferThread(this, interface_name, filter);
        catchPacketThread->start();
//        connect(catchPacketThread, &SnifferThread::sendData, this, &MainWindow::append_text, Qt::QueuedConnection);
        connect(catchPacketThread, &SnifferThread::sendData, this, &MainWindow::append_table, Qt::QueuedConnection);
        connect(catchPacketThread, &SnifferThread::sendData, this, &MainWindow::saveData, Qt::QueuedConnection);
        ui->startButton->setText("停止抓包");
    }
}


void MainWindow::on_countButton_clicked()
{
    QVector<QStringList> temp = packetVector;
    //ALL ARP IPv4 IPv6 TCP UDP ICMP TCPv6 UDPv6 ICMPV6
    u_int countPacket[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    countPacket[0] = temp.length();
    QVector<QStringList>::iterator iter;
    for (iter = temp.begin(); iter != temp.end(); iter++)
    {
        QString protocol = *(iter->end() - 3);
        if(protocol == "ARP"){
            countPacket[1]++;
        }else if(protocol == "IPv4"){
            countPacket[2]++;
        }else if(protocol == "TCP"){
            countPacket[2]++;
            countPacket[4]++;
        }else if(protocol == "UDP"){
            countPacket[2]++;
            countPacket[5]++;
        }else if(protocol == "ICMP"){
            countPacket[2]++;
            countPacket[6]++;
        }else if(protocol == "IPv6"){
            countPacket[3]++;
        }else if(protocol == "TCPv6"){
            countPacket[3]++;
            countPacket[7]++;
        }else if(protocol == "UDPv6"){
            countPacket[3]++;
            countPacket[8]++;
        }else if(protocol == "ICMPv6"){
            countPacket[3]++;
            countPacket[9]++;
        }
    }

    QMessageBox* MyBox = new QMessageBox();

    MyBox->setParent(this);
    MyBox->setWindowFlags(Qt::Dialog);

    MyBox->addButton("确定", QMessageBox::AcceptRole);

    MyBox->setWindowTitle("数据包统计");
    QStringList count;
    count << QString("\n数据包统计：")
          << QString::asprintf("%-10s%-20d%-10s%-20d\t", "ALL:", countPacket[0], "ARP:", countPacket[1])
          << QString::asprintf("%-10s%-20d%-10s%-20d\t", "IPv4:", countPacket[2], "IPv6:", countPacket[3])
          << QString::asprintf("%-10s%-20d%-10s%-20d\t", "TCP:", countPacket[4], "TCPv6", countPacket[7])
          << QString::asprintf("%-10s%-20d%-10s%-20d\t", "UDP:", countPacket[5], "UDPv6:", countPacket[8])
          << QString::asprintf("%-10s%-20d%-10s%-20d\t\n", "ICMP:", countPacket[6], "ICMPv6:", countPacket[9]);
    MyBox->setText(count.join('\n'));
    MyBox->exec();
}

/*
void MainWindow::append_text(int index, QStringList data, uint packet_len, const u_char *packet_data){
    //qDebug() << "增加" << index;
    ui->textEdit->append(QString::number(index));
    QString combinedString = data.join("\n");
    //qDebug() << combinedString;
    ui->textEdit->append(combinedString);
}
*/


/*data:
 * Ethernet II      [3]
 *    - ARP         [9]
 *    - IPv4        [11]
 *    - IPv6        [8]
 *        - TCP     [10]
 *        - UDP     [5]
 *        - ICMP    [6]
 *        - ICMPv6  [4]
 * Protocol Name    [1]
 * Timestamp        [1]
 * Packet Length    [1]
 */
void MainWindow::append_table(int index, QStringList data){
    QString timestamp, source, destination, protocol, length, info;
    //uint size = data.size();

    length = *(data.end() - 1);
    timestamp = *(data.end() - 2);
    protocol = *(data.end() - 3);
    //protocol = data.at(size - 3);
    //qDebug() << "protocol" << QString(protocol);

    if(protocol == "ARP") {
        source = data[8].split(": ")[1];
        destination = data[10].split(": ")[1];
        if(destination == "00:00:00:00:00:00"){
            info = QString("Who has %1? Tell %2").arg(data[11].split(": ")[1]).arg(data[9].split(": ")[1]);
        }else {
            info = QString("%1 is at %2").arg(data[9].split(": ")[8]).arg(data[7].split(": ")[1]);
        }
    }else if(protocol == "TCP" || protocol == "UDP" || protocol == "ICMP" || protocol == "IPv4"){
        source = data[12].split(": ")[1];
        destination = data[13].split(": ")[1];
        if(protocol == "ICMP"){
            info = data[14];
        }else if(protocol != "IPv4"){
            info = QString("Port: %1 → Port: %2").arg(data[14].split(": ")[1]).arg(data[15].split(": ")[1]);
        }else{
            info = data[10];
        }
    }else if(protocol == "TCPv6" || protocol == "UDPv6" || protocol == "ICMPv6" || protocol == "IPv6"){
        source = data[9].split(": ")[1];
        destination = data[10].split(": ")[1];
        if(protocol == "ICMPv6"){
            info = data[11];
        }else if(protocol != "IPv6"){
            info = QString("Port: %1 → Port: %2").arg(data[11].split(": ")[1]).arg(data[12].split(": ")[1]);
        }else{
            info = data[4];
        }
    }else{
        source = data[1].split(": ")[1];
        destination = data[0].split(": ")[1];
        info = data[2];
    }

    tableData -> insertRow(index);
    tableData -> setItem(index, 0, new QStandardItem(timestamp));
    tableData -> setItem(index, 1, new QStandardItem(source));
    tableData -> setItem(index, 2, new QStandardItem(destination));
    tableData -> setItem(index, 3, new QStandardItem(protocol));
    tableData -> setItem(index, 4, new QStandardItem(length));
    tableData -> setItem(index, 5, new QStandardItem(info));
    for(int i = 0; i < 6; i++){
        tableData -> item(index, i) ->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    }
    ui->tableView->setModel(tableData);
}


/*data:
 * Ethernet II      [3]
 *    - ARP         [9]
 *    - IPv4        [11]
 *    - IPv6        [8]
 *        - TCP     [10]
 *        - UDP     [5]
 *        - ICMP    [6]
 *        - ICMPv6  [4]
 * Protocol Name    [1]
 * Timestamp        [1]
 * Packet Length    [1]
 */
void MainWindow::showTree(QStringList data){

    treeData->clear();
    QString protocol = *(data.end() - 3);
    qDebug()<<"showtree: "<<protocol;
    //以太网头
    QStandardItem *ethernet = new QStandardItem("Ethernet II");
    treeData->setItem(0, 0, ethernet);
    for(int i = 0; i < 3; i++){
        qDebug()<<data[i];
        ethernet->appendRow(new QStandardItem(data[i]));
    }

    //IPv4
    if(protocol == "TCP" || protocol == "UDP" || protocol == "ICMP" || protocol == "IPv4"){
        QStandardItem *ipv4 = new QStandardItem("Internet Protocol Version 4");
        treeData->setItem(1, 0, ipv4);
        for (int i = 3; i < 14; i++) {
            ipv4->appendRow(new QStandardItem(data[i]));
        }
        //TCP
        if(protocol == "TCP"){
            QStandardItem *tcp = new QStandardItem("Transmission Control Protocol");
            treeData->setItem(2, 0, tcp);
            for(int i = 14; i < 24; i++){
                tcp->appendRow(new QStandardItem(data[i]));
            }
        }
        //UDP
        else if(protocol == "UDP"){
            QStandardItem *udp = new QStandardItem("User Datagram Protocol");
            treeData->setItem(2, 0, udp);
            for(int i = 14; i < 19; i++){
                udp->appendRow(new QStandardItem(data[i]));
            }
        }
        //ICMP
        else if(protocol == "ICMP"){
            QStandardItem *icmp = new QStandardItem("Internet Control Message Protocol");
            treeData->setItem(2, 0, icmp);
            for(int i = 14; i < 20; i++){
                icmp->appendRow(new QStandardItem(data[i]));
            }
        }
    }
    //IPv6
    else if(protocol == "TCPv6" || protocol == "UDPv6" || protocol == "ICMPv6" || protocol == "IPv4v6"){
        QStandardItem *ipv6 = new QStandardItem("Internet Protocol Version 6");
        treeData->setItem(1, 0, ipv6);
        for (int i = 3; i < 11; i++) {
            ipv6->appendRow(new QStandardItem(data[i]));
        }
        //TCP
        if(protocol == "TCPv6"){
            QStandardItem *tcp = new QStandardItem("Transmission Control Protocol");
            treeData->setItem(2, 0, tcp);
            for(int i = 11; i < 21; i++){
                tcp->appendRow(new QStandardItem(data[i]));
            }
        }
        //UDP
        else if(protocol == "UDPv6"){
            QStandardItem *udp = new QStandardItem("User Datagram Protocol");
            treeData->setItem(2, 0, udp);
            for(int i = 11; i < 16; i++){
                udp->appendRow(new QStandardItem(data[i]));
            }
        }
        //ICMP
        else if(protocol == "ICMPv6"){
            QStandardItem *icmp = new QStandardItem("Internet Control Message Protocol");
            treeData->setItem(2, 0, icmp);
            for(int i = 11; i < 17; i++){
                icmp->appendRow(new QStandardItem(data[i]));
            }
        }
    }
    //ARP
    else if(protocol == "ARP"){
        QStandardItem *arp = new QStandardItem("Address Resolution Protocol");
        treeData->setItem(1, 0, arp);
        for (int i = 3; i < 12; i++) {
            arp->appendRow(new QStandardItem(data[i]));
        }
    }
    ui->treeView->setModel(treeData);
}

void MainWindow::showBinary(packetData data){
    ui->rawTextEdit->clear();

    QString binaryText = "";
    u_int len = data.len;
    const u_char *pointer = data.packet_data;

    qDebug() << "数据包长度：" << len;
    for(u_int i = 0; pointer != nullptr && i < len; pointer++, i++){
        QString b = QString("%1").arg((*pointer), 2, 16, QLatin1Char('0'));
        ui->rawTextEdit->insertPlainText(b + " ");
    }
}

void MainWindow::on_tableView_doubleClicked(const QModelIndex &index)
{
    qDebug() << "双击" << index.row();

    //展示Tree
    QStringList temp = packetVector.at(index.row());
    showTree(temp);

    //展示原始数据包
    packetData temp2 = packetRaw.at(index.row());
    showBinary(temp2);
}

void MainWindow::saveData(int index, QStringList data, uint packet_len, const u_char *packet_data) {
    //存储数据包信息
//    qDebug() << "存储数据包信息进Vector"  << index;
    packetVector.push_back(data);

    //存储原始数据包
    packetData temp;
    temp.len = packet_len;
    temp.packet_data = packet_data;
    packetRaw.push_back(temp);
//    qDebug() << "存储原始数据包进Vector"   << index;
}

