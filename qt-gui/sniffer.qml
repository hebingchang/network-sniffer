import QtQuick 2.6
import QtQuick.Window 2.2
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import QtQuick.Extras 1.4
import QtGraphicalEffects 1.0
import QtQuick.Dialogs 1.3

Window {
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

    function savePacketDialog () {
        if (packetList.currentIndex == -1) {
            msgbox('错误', '未选择数据包。')
        } else {
            fileDialog.visible = true
        }
    }

    function msgbox (title, message) {
        messageDialog.title = title
        messageDialog.text = message
        messageDialog.visible = true
    }

    function toggleMenu () {
        console.log(btnSavePacket.opacity)
        btnSavePacket.opacity = 1 - btnSavePacket.opacity
        btnRebuildTCP.opacity = 1 - btnRebuildTCP.opacity
        plusImage.rotation = 225 - plusImage.rotation
        ease1.duration = 2500 - ease1.duration
        ease2.duration = 2500 - ease2.duration
    }

    id: mainWindow
    objectName: "mainWindow"
    visible: true
    width: 800
    height: 500
    title: qsTr("Sniffer")

    Text {
        id: lblDevice
        x: 12
        y: 11
        text: qsTr("选择网卡:")
    }

    Button {
        id: btnStart
        objectName: "btnStart"
        x: 394
        y: 5
        width: 96
        height: 27
        text: qsTr("开始抓包")
        anchors.right: parent.right
        anchors.rightMargin: 110
        focusPolicy: Qt.TabFocus
        display: AbstractButton.TextOnly
    }

    ComboBox {
        id: comboDevice
        objectName: "comboDevice"
        y: 5
        height: 28
        anchors.left: parent.left
        anchors.leftMargin: 80
        anchors.right: parent.right
        anchors.rightMargin: 212
        model: ListModel {
            id: devices
        }
    }

    Button {
        id: btnRefresh
        x: 496
        y: 5
        width: 96
        height: 27
        text: qsTr("刷新网卡")
        anchors.right: parent.right
        anchors.rightMargin: 8
        focusPolicy: Qt.TabFocus
        display: AbstractButton.TextOnly
        onClicked: {
            devices.clear()
        }
    }

    Label {
        id: lblSniffering
        x: 696
        y: 42
        width: 96
        height: 16
        color: "#f04444"
        text: "● 正在抓包"
        horizontalAlignment: Text.AlignRight
        verticalAlignment: Text.AlignVCenter
        visible: false
        anchors.right: parent.right
        anchors.rightMargin: 8
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

    GroupBox {
        id: groupPacket
        y: 42
        height: 0.42 * mainWindow.height
        anchors.right: parent.right
        anchors.rightMargin: 8
        anchors.left: parent.left
        anchors.leftMargin: 8
        title: qsTr("数据包")

        ListView {
            id: packetList
            anchors.top: parent.top
            anchors.topMargin: 32
            anchors.left: parent.left
            anchors.leftMargin: 7
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 7
            anchors.right: parent.right
            anchors.rightMargin: 7
            parent: groupPacket
            highlightRangeMode: ListView.NoHighlightRange
            ScrollBar.vertical: ScrollBar {}
            headerPositioning: ListView.OverlayHeader
            highlightMoveDuration : 1000
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
                        width: 5 / 75 * packetList.width
                    }
                    spacing: 10
                    Text {
                        text: '源地址'
                        anchors.verticalCenter: parent.verticalCenter
                        font.bold: true
                        width: 24 / 75 * packetList.width
                    }
                    Text {
                        text: '目的地址'
                        anchors.verticalCenter: parent.verticalCenter
                        font.bold: true
                        width: 24 / 75 * packetList.width
                    }
                    Text {
                        text: '协议'
                        anchors.verticalCenter: parent.verticalCenter
                        font.bold: true
                        width: 8 / 75 * packetList.width
                    }
                    Text {
                        text: '长度'
                        anchors.verticalCenter: parent.verticalCenter
                        font.bold: true
                        width: 5 / 75 * packetList.width
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
                        elide: Text.ElideRight
                        width: 5 / 75 * packetList.width
                    }
                    spacing: 10
                    Text {
                        text: source
                        anchors.verticalCenter: parent.verticalCenter
                        verticalAlignment: Text.AlignVCenter
                        // horizontalAlignment: Text.AlignHCenter
                        font.bold: false
                        font.family: 'Courier'
                        elide: Text.ElideRight
                        width: 24 / 75 * packetList.width
                    }
                    Text {
                        text: destination
                        anchors.verticalCenter: parent.verticalCenter
                        verticalAlignment: Text.AlignVCenter
                        // horizontalAlignment: Text.AlignHCenter
                        font.bold: false
                        font.family: 'Courier'
                        elide: Text.ElideRight
                        width: 24 / 75 * packetList.width
                    }
                    Text {
                        text: protocol
                        anchors.verticalCenter: parent.verticalCenter
                        verticalAlignment: Text.AlignVCenter
                        // horizontalAlignment: Text.AlignHCenter
                        font.bold: false
                        font.family: 'Courier'
                        elide: Text.ElideRight
                        width: 8 / 75 * packetList.width
                    }
                    Text {
                        text: length
                        anchors.verticalCenter: parent.verticalCenter
                        verticalAlignment: Text.AlignVCenter
                        // horizontalAlignment: Text.AlignHCenter
                        font.bold: false
                        font.family: 'Courier'
                        elide: Text.ElideRight
                        width: 5 / 75 * packetList.width
                    }
                }
            }
            model: ListModel {
                id: packetModel
                objectName: "packetModel"
            }
        }
    }

    RoundButton {
        id: btnMenu
        x: 448
        y: 442
        text: qsTr("")
        z: 999
        rightPadding: 0
        leftPadding: 0
        bottomPadding: 5
        topPadding: 0
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 18
        anchors.right: parent.right
        anchors.rightMargin: 12

        Image {
            id: plusImage
            width: parent.width / 2.5
            height: parent.height / 2.5
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.verticalCenter: parent.verticalCenter
            source: 'images/plus.svg'
            Behavior on rotation { PropertyAnimation {
                properties: "rotation";
                easing.type: Easing.InOutQuad
                duration: 1000
            } }
        }

        onClicked: toggleMenu()
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

    RoundButton {
        id: btnSavePacket
        x: 753
        y: 406
        width: 30
        height: 30
        text: qsTr("")
        visible: true
        z: 999
        leftPadding: 0
        anchors.right: parent.right
        anchors.bottomMargin: 64
        Image {
            id: plusImage1
            width: 15
            height: 15
            anchors.verticalCenterOffset: 1
            anchors.horizontalCenterOffset: 1
            anchors.horizontalCenter: parent.horizontalCenter
            source: "images/save.svg"
            anchors.verticalCenter: parent.verticalCenter
        }

        Behavior on opacity { PropertyAnimation {
            id: ease1
            properties: "opacity"
            easing.type: Easing.InOutQuad
            duration: 1000
        } }

        topPadding: 0
        anchors.rightMargin: 17
        rightPadding: 0
        anchors.bottom: parent.bottom
        bottomPadding: 5
        onClicked: savePacketDialog()
        ToolTip.visible: hovered
        ToolTip.text: qsTr("导出数据包文本")
        opacity: 0
    }

    RoundButton {
        id: btnRebuildTCP
        x: 753
        y: 370
        width: 30
        height: 30
        text: qsTr("")
        leftPadding: 0
        z: 999
        anchors.right: parent.right
        anchors.bottomMargin: 100
        Image {
            id: plusImage2
            width: parent.width / 2.5
            height: parent.height / 2.5
            anchors.horizontalCenter: parent.horizontalCenter
            source: "images/plus.svg"
            anchors.verticalCenter: parent.verticalCenter
        }
        Behavior on opacity { PropertyAnimation {
            id: ease2
            properties: "opacity"
            easing.type: Easing.InOutQuad
            duration: 1500
        } }
        topPadding: 0
        anchors.rightMargin: 17
        rightPadding: 0
        anchors.bottom: parent.bottom
        bottomPadding: 5
        ToolTip.visible: hovered
        ToolTip.text: qsTr("导出 TCP 分片数据")
        opacity: 0
    }

    FileDialog {
        id: fileDialog
        title: "另存为数据包"
        folder: shortcuts.home
        nameFilters: [ "文本文档 (*.txt)" ]
        onAccepted: {
            parse.savePacket(packetList.currentIndex, fileDialog.fileUrls)
        }
        onRejected: {
            console.log("Canceled")
        }
        selectExisting: false
        selectMultiple: false
    }

    MessageDialog {
        id: messageDialog
        title: ""
        text: ""
    }
}

/*##^## Designer {
    D{i:3;anchors_width:259;anchors_x:73}D{i:6;anchors_height:172;anchors_width:771;anchors_x:7;anchors_y:32}
}
 ##^##*/
