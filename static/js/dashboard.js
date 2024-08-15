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

    // Simulate receiving notifications
    setInterval(function() {
        const notification = `<li class="list-group-item">New notification at ${new Date().toLocaleTimeString()}</li>`;
        document.getElementById("notifications-list").insertAdjacentHTML('beforeend', notification);
    }, 5000);
});
