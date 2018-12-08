import QtQuick 2.6
import QtQuick.Window 2.2
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import QtQuick.Extras 1.4
import QtGraphicalEffects 1.0

Window {
    function initPieMenu () {
        pieMenu.addItem('开始抓包')
        pieMenu.menuItems[0].onTriggered = function () { startSnifferAction() }
    }

    function setDevModel(dev) {
        comboDevice.model = dev
    }

    function appendPacketModel(packet) {
        packetModel.append(packet)
        groupPacket.title = '数据包 (' + packetModel.rowCount() + ')'
    }

    function startSnifferAction() {
        btnStart.text = '停止抓包'
        mainWindow.title = 'Sniffer - 正在抓包'
        lblSniffering.visible = true
        btnRefresh.visible = false
    }

    function stopSnifferAction() {
        btnStart.text = '开始抓包'
        mainWindow.title = 'Sniffer'
        lblSniffering.visible = false
        btnRefresh.visible = true
    }

    function changeItem (index) {
        var data = JSON.parse(parse.onItemChange(index))

        parseAccordion.model = data

        packetList.currentIndex = index
    }

    id: mainWindow
    objectName: "mainWindow"
    visible: true
    width: 500
    height: 500
    title: qsTr("Sniffer")

    Text {
        id: lblDevice
        x: 15
        y: 11
        text: qsTr("选择网卡:")
        font.pixelSize: 12
    }

    Button {
        id: btnStart
        objectName: "btnStart"
        x: 343
        y: 8
        width: 67
        height: 22
        text: qsTr("开始抓包")
        anchors.right: parent.right
        anchors.rightMargin: 90
        font.pointSize: 11
        focusPolicy: Qt.TabFocus
        display: AbstractButton.TextOnly
    }

    ComboBox {
        id: comboDevice
        objectName: "comboDevice"
        y: 5
        height: 28
        anchors.left: parent.left
        anchors.leftMargin: 73
        anchors.right: parent.right
        anchors.rightMargin: 168
        model: ListModel {
            id: devices
        }
    }

    Button {
        id: btnRefresh
        x: 421
        y: 8
        width: 67
        height: 22
        text: qsTr("刷新网卡")
        anchors.right: parent.right
        anchors.rightMargin: 12
        font.pointSize: 11
        focusPolicy: Qt.TabFocus
        display: AbstractButton.TextOnly
        onClicked: {
            devices.clear()
        }
    }

    ListView {
        id: packetList
        parent: groupPacket
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 10
        anchors.top: parent.top
        anchors.topMargin: 33
        anchors.right: parent.right
        anchors.rightMargin: 15
        anchors.left: parent.left
        anchors.leftMargin: 12
        highlightRangeMode: ListView.NoHighlightRange
        ScrollBar.vertical: ScrollBar {}
        headerPositioning: ListView.OverlayHeader
        clip: true
        highlight: Rectangle { color: "lightsteelblue"; radius: 0 }
        header: Item {
          id: headerItem
          width: packetList.width
          height: 30
          z: 2
          Rectangle {
              color: 'white'
              width: packetList.width
              height: 30
          }

          Row {
              id: rowHeader

              Text {
                  text: '#'
                  anchors.verticalCenter: parent.verticalCenter
                  font.bold: true
                  width: 30
              }
              spacing: 10
              Text {
                  text: '源地址'
                  anchors.verticalCenter: parent.verticalCenter
                  font.bold: true
                  width: 160
              }
              Text {
                  text: '目的地址'
                  anchors.verticalCenter: parent.verticalCenter
                  font.bold: true
                  width: 160
              }
              Text {
                  text: '协议'
                  anchors.verticalCenter: parent.verticalCenter
                  font.bold: true
                  width: 80
              }
              Text {
                  text: '长度'
                  anchors.verticalCenter: parent.verticalCenter
                  font.bold: true
                  width: 50
              }
          }
        }
        delegate: Item {
            x: 5
            width: packetList.width
            height: 20
            MouseArea {
                anchors.fill: parent
                onClicked: {
                    changeItem(index)
                }
            }
            Row {
                id: row1

                Text {
                    text: id
                    anchors.verticalCenter: parent.verticalCenter
                    verticalAlignment: Text.AlignVCenter
                    font.bold: true
                    width: 30
                }
                spacing: 10
                Text {
                    text: source
                    anchors.verticalCenter: parent.verticalCenter
                    verticalAlignment: Text.AlignVCenter
                    // horizontalAlignment: Text.AlignHCenter
                    font.bold: false
                    font.family: 'Courier'
                    width: 160
                }
                Text {
                    text: destination
                    anchors.verticalCenter: parent.verticalCenter
                    verticalAlignment: Text.AlignVCenter
                    // horizontalAlignment: Text.AlignHCenter
                    font.bold: false
                    font.family: 'Courier'
                    width: 160
                }
                Text {
                    text: protocol
                    anchors.verticalCenter: parent.verticalCenter
                    verticalAlignment: Text.AlignVCenter
                    // horizontalAlignment: Text.AlignHCenter
                    font.bold: false
                    font.family: 'Courier'
                    width: 80
                }
                Text {
                    text: length
                    anchors.verticalCenter: parent.verticalCenter
                    verticalAlignment: Text.AlignVCenter
                    // horizontalAlignment: Text.AlignHCenter
                    font.bold: false
                    font.family: 'Courier'
                    width: 50
                }
            }
        }
        model: ListModel {
            id: packetModel
            objectName: "packetModel"
        }
    }

    Label {
        id: lblSniffering
        x: 112
        y: 43
        width: 67
        height: 16
        color: "#f04444"
        text: "● 正在抓包"
        verticalAlignment: Text.AlignVCenter
        visible: false
        anchors.right: parent.right
        anchors.rightMargin: 321
        NumberAnimation on opacity {
            id: animationIn
            to: 1
            duration: 2000
            running: true
            onStopped: {
                animationOut.start()
            }
        }
        NumberAnimation on opacity {
            id: animationOut
            to: 0
            duration: 2000
            onStopped: {
                animationIn.start()
            }
        }
    }

    PieMenu {
        id: pieMenu
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        acceptedButtons: Qt.RightButton

        onClicked: pieMenu.popup(mouseX, mouseY)
    }

    GroupBox {
        id: groupPacket
        y: 42
        height: 0.42 * mainWindow.height
        anchors.right: parent.right
        anchors.rightMargin: 8
        anchors.left: parent.left
        anchors.leftMargin: 8
        title: qsTr("数据包")
    }

    RoundButton {
        id: btnMenu
        x: 448
        y: 442
        z: 999
        text: "+"
        rightPadding: 0
        leftPadding: 0
        bottomPadding: 5
        topPadding: 0
        font.pointSize: 26
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 18
        anchors.right: parent.right
        anchors.rightMargin: 12

        onClicked: pieMenu.popup(mouseX, mouseY)
    }

    GroupBox {
        id: groupParse
        y: 255
        height: mainWindow.height - groupPacket.height - 60
        anchors.right: parent.right
        anchors.rightMargin: 8
        anchors.left: parent.left
        anchors.leftMargin: 8
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 13
        title: qsTr("报文解析")

        Accordion {
            anchors.rightMargin: 0
            anchors.bottomMargin: 0
            anchors.leftMargin: -12
            anchors.topMargin: 0
            anchors.fill: parent
            anchors.margins: 10
            id: parseAccordion
        }
    }
}

/*##^## Designer {
    D{i:3;anchors_width:259;anchors_x:73}D{i:6;anchors_height:221;anchors_width:473;anchors_x:6;anchors_y:33}
D{i:119;anchors_height:181;anchors_width:460;anchors_x:0;anchors_y:0}
}
 ##^##*/
