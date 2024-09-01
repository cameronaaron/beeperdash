document.addEventListener('DOMContentLoaded', function() {
    // Tooltip initialization
    $('[data-toggle="tooltip"]').tooltip();

    // Form validation
    (function() {
        'use strict';
        window.addEventListener('load', function() {
            var forms = document.getElementsByClassName('needs-validation');
            Array.prototype.filter.call(forms, function(form) {
                form.addEventListener('submit', function(event) {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            });
        }, false);
    })();

    // Post Bridge State Form submission
    document.getElementById('postBridgeStateForm').addEventListener('submit', async function(event) {
        event.preventDefault();

        const form = event.target;
        const formData = new FormData(form);
        const responseDiv = document.getElementById('postBridgeStateResponse');

        try {
            const response = await fetch('/post_bridge_state', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': getCookie('csrftoken') // Assuming Django CSRF token
                }
            });

            const result = await response.text();
            if (response.ok) {
                responseDiv.innerHTML = `<div class="alert alert-success">${result}</div>`;
            } else {
                responseDiv.innerHTML = `<div class="alert alert-danger">${result}</div>`;
            }
        } catch (error) {
            responseDiv.innerHTML = `<div class="alert alert-danger">An error occurred: ${error.message}</div>`;
        }
    });

    // Check Other Bridge input
    document.getElementById('other_bridge').addEventListener('input', function() {
        var otherBridgeInput = document.getElementById('other_bridge');
        var bridgeSelect = document.getElementById('bridge');
        if (otherBridgeInput.value.trim() !== '') {
            bridgeSelect.value = 'other';
        }
    });

    // Set Bridge Name
    document.getElementById('start_or_update_bridge').addEventListener('submit', function() {
        var otherBridgeInput = document.getElementById('other_bridge');
        var bridgeSelect = document.getElementById('bridge');
        if (otherBridgeInput.value.trim() !== '') {
            bridgeSelect.name = ''; // Disable the dropdown name
            otherBridgeInput.name = 'name'; // Use the text box name
        }
    });
});

// Function to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}