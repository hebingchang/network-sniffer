import QtQuick 2.4
import QtQuick.Controls 2.2

Column {
    width: parent.width
    height: parent.height

    property alias model: columnRepeater.model

    ListView {
        id: columnRepeater
        delegate: accordion

        width: parent.width
        height: parent.height
        clip: true

        model: ListModel { }

        ScrollBar.vertical: ScrollBar { }
    }

    Component {
        id: accordion
        Column {
            width: parent.width

            Item {
                id: infoRow

                width: parent.width
                height: childrenRect.height
                property bool expanded: false

                MouseArea {
                    anchors.fill: parent
                    onClicked: infoRow.expanded = !infoRow.expanded
                    enabled: modelData.children ? true : false
                }

                Image {
                    id: carot

                    anchors {
                        top: parent.top
                        left: parent.left
                        margins: 5
                    }

                    sourceSize.width: 16
                    sourceSize.height: 16
                    source: 'images/right-triangle.svg'
                    visible: modelData.children ? true : false
                    transform: Rotation {
                        origin.x: 10
                        origin.y: 8
                        angle: infoRow.expanded ? 90 : 0
                        Behavior on angle { NumberAnimation { duration: 150 } }
                    }
                }

                Text {
                    anchors {
                        left: carot.visible ? carot.right : parent.left
                        top: parent.top
                        margins: 5
                    }

                    font.bold: modelData.bold ? true : false
                    visible: parent.visible

                    color: 'black'
                    text: modelData.label
                }

                Text {
                    visible: infoRow.visible

                    color: 'black'
                    text: modelData.value
                    font.family: 'Courier'

                    anchors {
                        top: parent.top
                        right: parent.right
                        margins: 5
                    }
                }
            }

            ListView {
                id: subentryColumn
                x: 20
                width: parent.width - x
                height: childrenRect.height * opacity
                visible: opacity > 0
                opacity: infoRow.expanded ? 1 : 0
                delegate: accordion
                model: modelData.children ? modelData.children : []
                interactive: false
                Behavior on opacity { NumberAnimation { duration: 200 } }
            }
        }
    }
}
