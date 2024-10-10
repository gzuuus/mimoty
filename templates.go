package main

import (
	"html/template"
	"log"
	"net/http"
)

var templates *template.Template

func InitTemplates() {
	var err error
	templates, err = template.New("").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.RelayName}} - Subkey Management</title>
    <script src="https://unpkg.com/htmx.org@1.9.2"></script>
    <script src="https://unpkg.com/nostr-tools/lib/nostr.bundle.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>

    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        .card {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .input, .button {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .button {
            background-color: #3498db;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        .button:hover {
            background-color: #2980b9;
        }
        .subkey-list {
            margin-top: 20px;
            overflow-x: auto;
        }
        .subkey-table {
            width: 100%;
            border-collapse: collapse;
        }
        .subkey-table th, .subkey-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .subkey-table th {
            background-color: #f2f2f2;
        }
        .qr-code {
            display: none;
            margin-top: 10px;
        }
        .show-qr, .hide-qr {
            background-color: #2ecc71;
            margin-left: 10px;
        }
        .hide-qr {
            display: none;
        }
        .checkbox-column {
            width: 30px;
        }
        .key-column {
            max-width: 200px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.RelayName}} - Subkey Management</h1>
        
        <div class="card" id="login-section">
            <h2>Login</h2>
            <button id="login-button" class="button" onclick="login()">Login with Nostr</button>
        </div>

        <div class="card" id="subkey-management" style="display: none;">
            <h2>Manage Subkeys</h2>
            <form id="add-subkey-form">
                <input type="text" name="privkey" placeholder="Private Key (nsec or hex)" class="input" required>
                <input type="text" name="allowed_kinds" placeholder="Allowed Kinds (comma-separated)" class="input" required>
                <button type="submit" class="button">Add Subkey</button>
            </form>

            <div id="subkey-list" class="subkey-list">
                <table class="subkey-table">
                    <thead>
                        <tr>
                            <th class="checkbox-column"><input type="checkbox" id="select-all"></th>
                            <th>Public Key</th>
                            <th>Private Key</th>
                            <th>Allowed Kinds</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="subkey-table-body">
                        <!-- Subkeys will be loaded here -->
                    </tbody>
                </table>
                <button id="delete-selected" class="button" style="display: none;">Delete Selected</button>
            </div>
        </div>
    </div>

    <script>
    const tokenCache = new Map();

    async function getAuthToken(url, method) {
        const cacheKey = url + ':' + method;
        if (tokenCache.has(cacheKey)) {
            const cachedToken = tokenCache.get(cacheKey);
            if (Date.now() - cachedToken.timestamp < 4 * 60 * 1000) { // 4 minutes
                return cachedToken.token;
            }
        }
        
        const token = await generateAuthToken(url, method);
        tokenCache.set(cacheKey, { token, timestamp: Date.now() });
        return token;
    }

    async function generateAuthToken(url, method) {
        const authEvent = {
            kind: 27235,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["u", url], ["method", method]],
            content: ""
        };
        const signedEvent = await window.nostr.signEvent(authEvent);
        return btoa(JSON.stringify(signedEvent));
    }

    async function login() {
        try {
            const token = await getAuthToken('/api/login', 'POST');
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Authorization': 'Nostr ' + token
                }
            });

            if (response.ok) {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('subkey-management').style.display = 'block';
                loadSubkeys();
            } else {
                throw new Error('Login failed');
            }
        } catch (err) {
            console.error('Login failed:', err);
            alert('Login failed. Make sure you have the correct Nostr extension installed and are using the root key.');
        }
    }

    async function loadSubkeys() {
        const token = await getAuthToken('/api/subkeys', 'GET');
        const response = await fetch('/api/subkeys', {
            headers: {
                'Authorization': 'Nostr ' + token
            }
        });
        const subkeys = await response.json();
        const subkeyTableBody = document.getElementById('subkey-table-body');
        subkeyTableBody.innerHTML = '';
        subkeys.forEach(subkey => {
            const row = document.createElement('tr');
            row.innerHTML = ` + "`" + `
                <td><input type="checkbox" class="subkey-checkbox" data-pubkey="${subkey.pubkey}"></td>
                <td class="key-column">
                    ${subkey.pubkey}
                    <br>
                    <button class="show-qr" onclick="showQR(this, '${subkey.pubkey}')">Show QR</button>
                    <button class="hide-qr" onclick="hideQR(this)">Hide QR</button>
                    <div class="qr-code"></div>
                </td>
                <td class="key-column">${subkey.privkey}</td>
                <td>${subkey.allowed_kinds}</td>
                <td>
                    <button onclick="deleteSubkey('${subkey.pubkey}')" class="button delete">Delete</button>
                </td>
            ` + "`" + `;
            subkeyTableBody.appendChild(row);
        });
        updateDeleteSelectedButton();
    }

    function showQR(button, pubkey) {
        const qrContainer = button.nextElementSibling.nextElementSibling;
        qrContainer.innerHTML = '';
        new QRCode(qrContainer, {
            text: pubkey,
            width: 128,
            height: 128
        });
        qrContainer.style.display = 'block';
        button.style.display = 'none';
        button.nextElementSibling.style.display = 'inline-block';
    }

    function hideQR(button) {
        const qrContainer = button.nextElementSibling;
        qrContainer.style.display = 'none';
        button.style.display = 'none';
        button.previousElementSibling.style.display = 'inline-block';
    }

    document.getElementById('select-all').addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('.subkey-checkbox');
        checkboxes.forEach(checkbox => checkbox.checked = this.checked);
        updateDeleteSelectedButton();
    });

    document.getElementById('subkey-table-body').addEventListener('change', function(e) {
        if (e.target.classList.contains('subkey-checkbox')) {
            updateDeleteSelectedButton();
        }
    });

    function updateDeleteSelectedButton() {
        const deleteSelectedButton = document.getElementById('delete-selected');
        const checkedBoxes = document.querySelectorAll('.subkey-checkbox:checked');
        deleteSelectedButton.style.display = checkedBoxes.length > 0 ? 'block' : 'none';
    }

    document.getElementById('delete-selected').addEventListener('click', async function() {
        const checkedBoxes = document.querySelectorAll('.subkey-checkbox:checked');
        const pubkeys = Array.from(checkedBoxes).map(checkbox => checkbox.dataset.pubkey);
        
        for (const pubkey of pubkeys) {
            await deleteSubkey(pubkey);
        }
        
        loadSubkeys();
    });

    async function deleteSubkey(pubkey) {
        const token = await getAuthToken('/api/subkey/' + pubkey, 'DELETE');
        const response = await fetch("/api/subkey/" + pubkey, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Nostr ' + token
            }
        });

        if (response.ok) {
            console.log("Deleted subkey:", pubkey);
            loadSubkeys();
        } else {
            alert('Failed to delete subkey');
        }
    }

    async function addSubkey(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        let privkey = formData.get('privkey').trim();
        const allowedKinds = formData.get('allowed_kinds').split(',').map(k => k.trim()).join(',');
        
        const subkey = {
            privkey: privkey,
            allowed_kinds: allowedKinds
        };

        const token = await getAuthToken('/api/subkey', 'POST');

        const response = await fetch('/api/subkey', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Nostr ' + token
            },
            body: JSON.stringify(subkey)
        });

        if (response.ok) {
            const result = await response.json();
            console.log("Added subkey with pubkey:", result.pubkey);
            form.reset();
            loadSubkeys();
        } else {
            alert('Failed to add subkey');
        }
    }

    document.getElementById('add-subkey-form').addEventListener('submit', addSubkey);
    </script>
</body>
</html>
`)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}
}

func RenderTemplate(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "text/html")
	err := templates.ExecuteTemplate(w, "", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
