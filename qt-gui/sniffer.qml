import QtQuick 2.6
import QtQuick.Window 2.2
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import QtQuick.Extras 1.4
import QtGraphicalEffects 1.0
import QtQuick.Dialogs 1.3

Window {
    property bool menuOpen: false

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

    function clearList() {
        packetModel.clear()
    }

    function savePacketDialog (type) {
        if (type === 0) {                                    // 另存为数据包
            if (packetList.currentIndex == -1) {
                msgbox('错误', '未选择数据包。')
            } else {
                fileDialog.title = '另存为数据包'
                fileDialog.nameFilters = ["文本文档 (*.txt)"]
                fileDialog.visible = true
            }
        } else if (type === 1) {                                    // 保存TCP
            if (packetList.currentIndex == -1) {
                msgbox('错误', '未选择数据包。')
            } else {
                fileDialog.title = '保存 TCP 分段数据'
                fileDialog.nameFilters = ["所有文件 (*.*)"]
                fileDialog.visible = true
            }
        }
    }

    function msgbox (title, message) {
        messageDialog.title = title
        messageDialog.text = message
        messageDialog.visible = true
    }

    function toggleMenu () {
        btnSavePacket.visible = true
        btnRebuildTCP.visible = true
        btnSearch.visible = true

        if (menuOpen) {
            menuOpen = false
            btnSavePacket.opacity = 0
            btnRebuildTCP.opacity = 0
            btnSearch.opacity = 0

            plusImage.rotation = 0

            ease1.duration = 600
            ease2.duration = 900
            ease3.duration = 1200
        } else {
            menuOpen = true
            btnSavePacket.opacity = 1
            btnRebuildTCP.opacity = 1
            btnSearch.opacity = 1

            plusImage.rotation = 225

            ease1.duration = 1200
            ease2.duration = 900
            ease3.duration = 600
        }
    }

    id: mainWindow
    objectName: "mainWindow"
    visible: true
    width: 800
    height: 550
    title: qsTr("Sniffer")

    Text {
        id: lblDevice
        x: 20
        y: 10
        text: qsTr("选择网卡:")
    }

    Button {
        id: btnStart
        objectName: "btnStart"
        x: 696
        y: 42
        width: 96
        height: 27
        text: qsTr("开始抓包")
        anchors.right: parent.right
        anchors.rightMargin: 8
        focusPolicy: Qt.TabFocus
        display: AbstractButton.TextOnly
    }

    ComboBox {
        id: comboDevice
        objectName: "comboDevice"
        y: 5
        height: 28
        anchors.left: parent.left
        anchors.leftMargin: 93
        anchors.right: parent.right
        anchors.rightMargin: 122
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
        y: 80
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
        x: 8
        y: 80
        height: 0.36 * mainWindow.height
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
            highlightResizeDuration: 800
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
        opacity: 0.5
        z: 999
        rightPadding: 0
        leftPadding: 0
        bottomPadding: 5
        topPadding: 0
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 18
        anchors.right: parent.right
        anchors.rightMargin: 12

        onHoveredChanged: {
            if (hovered) {
                btnMenu.opacity = 1
            } else {
                btnMenu.opacity = 0.5
            }
        }

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
        height: mainWindow.height - groupPacket.height - 100
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
        visible: false
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
            duration: 600
            onRunningChanged: {
                if (btnSavePacket.opacity == 0 && (!running)) {
                    btnSavePacket.visible = false
                }
            }
        } }

        topPadding: 0
        anchors.rightMargin: 17
        rightPadding: 0
        anchors.bottom: parent.bottom
        bottomPadding: 5
        onClicked: savePacketDialog(0)
        ToolTip.visible: hovered
        ToolTip.text: qsTr("导出数据包文本")
        opacity: 0
    }

    RoundButton {
        id: btnSearch
        x: 753
        y: 384
        width: 30
        height: 30
        text: qsTr("")
        visible: false
        leftPadding: 0
        z: 999
        anchors.right: parent.right
        anchors.bottomMargin: 136
        Image {
            id: plusImage3
            width: parent.width / 2.5
            height: parent.height / 2.5
            anchors.horizontalCenter: parent.horizontalCenter
            source: "images/search.svg"
            anchors.verticalCenter: parent.verticalCenter
        }
        Behavior on opacity { PropertyAnimation {
            id: ease3
            properties: "opacity"
            easing.type: Easing.InOutQuad
            duration: 1200
            onRunningChanged: {
                if (btnSearch.opacity == 0 && (!running)) {
                    btnSearch.visible = false
                }
            }
        } }
        topPadding: 0
        anchors.rightMargin: 17
        rightPadding: 0
        anchors.bottom: parent.bottom
        bottomPadding: 5
        ToolTip.visible: hovered
        ToolTip.text: qsTr("搜索数据包")
        onClicked: {
            searchPrompt.visible = true
        }

        opacity: 0
    }

    RoundButton {
        id: btnRebuildTCP
        x: 753
        y: 370
        width: 30
        height: 30
        text: qsTr("")
        visible: false
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
            duration: 900
            onRunningChanged: {
                if (btnRebuildTCP.opacity == 0 && (!running)) {
                    btnRebuildTCP.visible = false
                }
            }
        } }
        topPadding: 0
        anchors.rightMargin: 17
        rightPadding: 0
        anchors.bottom: parent.bottom
        bottomPadding: 5
        ToolTip.visible: hovered
        onClicked: savePacketDialog(1)
        ToolTip.text: qsTr("导出 TCP 分段数据")
        opacity: 0
    }

    FileDialog {
        id: fileDialog
        title: "另存为数据包"
        folder: shortcuts.home
        nameFilters: [ "文本文档 (*.txt)" ]

        onAccepted: {
            if (fileDialog.title === '另存为数据包') {
                parse.savePacket(packetList.currentIndex, fileDialog.fileUrls)
            } else {
                let ret = parse.saveTCP(packetList.currentIndex, fileDialog.fileUrls)
                msgbox('提示', ret)
            }
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

    Dialog {
        id: searchPrompt
        visible: false
        title: "搜索数据包"

        contentItem: Rectangle {
            implicitWidth: 450
            implicitHeight: 100
            Text {
                text: "关键字: "
                // anchors.centerIn: parent
                x: 10
                y: 10
            }
            TextField {
                id: txtKeyword
                x: 60
                y: 6
                width: 300
                height: 28
                text: qsTr("")
                opacity: 0.8
            }
            Button {
                id: btnDoSearch
                objectName: "btnStart"
                x: 376
                y: 6
                width: 60
                height: 28
                text: qsTr("搜索")
                display: AbstractButton.TextOnly
                onClicked: {
                    let result = parse.search(txtKeyword.text)
                    txtResult.text = result
                }
            }

            Button {
                id: btnCloseSearch
                objectName: "btnCloseSearch"
                x: 376
                y: 40
                width: 60
                height: 28
                text: qsTr("关闭")
                display: AbstractButton.TextOnly
                onClicked: {
                    searchPrompt.visible = false
                }
            }

            Text {
                id: txtResult
                text: ""
                x: 10
                y: 40
                width: 350
                wrapMode: Text.WordWrap
            }

        }
    }

    Text {
        id: lblDevice1
        x: 20
        y: 46
        text: qsTr("过滤器:")
    }

    TextField {
        id: txtFilter
        x: 93
        y: 42
        width: 585
        height: 28
        text: qsTr("")
        opacity: 0.8
        onTextChanged: {
            parse.setFilter(txtFilter.text)
        }
    }
}

/*##^## Designer {
    D{i:3;anchors_width:259;anchors_x:73}D{i:6;anchors_height:172;anchors_width:771;anchors_x:7;anchors_y:32}
}
 ##^##*/
