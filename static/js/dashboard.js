document.addEventListener("DOMContentLoaded", function() {
    // WebSocket for real-time bridge status updates
    const bridgeStatusSocket = new WebSocket("ws://localhost:8000/ws/bridge_status");

    bridgeStatusSocket.onmessage = function(event) {
        const bridgeStatus = JSON.parse(event.data);
        const bridgeStatusItem = `<li class="list-group-item">${bridgeStatus.bridge_name}: ${bridgeStatus.status}</li>`;
        document.getElementById("bridge-status-list").insertAdjacentHTML('beforeend', bridgeStatusItem);
    };

    bridgeStatusSocket.onclose = function(event) {
        console.log("WebSocket closed: ", event);
    };

    // WebSocket for real-time notifications
    const notificationsSocket = new WebSocket("ws://localhost:8000/ws/notifications");

    notificationsSocket.onmessage = function(event) {
        const notification = JSON.parse(event.data);
        const notificationItem = `<li class="list-group-item">${notification.issue_type}: ${notification.issue_description}</li>`;
        document.getElementById("notifications-list").insertAdjacentHTML('beforeend', notificationItem);
    };

    notificationsSocket.onclose = function(event) {
        console.log("WebSocket closed: ", event);
    };
});
