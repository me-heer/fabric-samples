document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = 'http://localhost:8081/api'; // Changed to port 8081

    // Get elements
    const initLedgerBtn = document.getElementById('initLedgerBtn');
    const initLedgerStatus = document.getElementById('initLedgerStatus');

    const refreshAssetsBtn = document.getElementById('refreshAssetsBtn');
    const allAssetsStatus = document.getElementById('allAssetsStatus');
    const assetTableBody = document.querySelector('#assetTable tbody');

    const createAssetForm = document.getElementById('createAssetForm');
    const createAssetStatus = document.getElementById('createAssetStatus');

    const queryAssetForm = document.getElementById('queryAssetForm');
    const queryAssetStatus = document.getElementById('queryAssetStatus');
    const queryAssetResult = document.getElementById('queryAssetResult');

    const transferAssetForm = document.getElementById('transferAssetForm');
    const transferAssetStatus = document.getElementById('transferAssetStatus');

    const errorTestBtn = document.getElementById('errorTestBtn');
    const errorTestStatus = document.getElementById('errorTestStatus');
    const errorTestResult = document.getElementById('errorTestResult');

    // Helper to display status messages
    function showStatus(element, message, type) {
        element.textContent = message;
        element.className = `status-message ${type}`; // 'success', 'error', 'info'
        element.style.display = 'block';
    }

    function hideStatus(element) {
        element.style.display = 'none';
        element.textContent = '';
        element.className = 'status-message';
    }

    // Function to fetch and display all assets
    async function fetchAllAssets() {
        showStatus(allAssetsStatus, 'Fetching all assets...', 'info');
        assetTableBody.innerHTML = ''; // Clear existing table rows

        try {
            const response = await fetch(`${API_BASE_URL}/assets`);
            const data = await response.json();

            if (!response.ok) {
                showStatus(allAssetsStatus, `Error: ${data.message || 'Failed to fetch assets'}`, 'error');
                return;
            }

            if (data.assets && data.assets.length > 0) {
                data.assets.forEach(asset => {
                    const row = assetTableBody.insertRow();
                    row.insertCell().textContent = asset.ID;
                    row.insertCell().textContent = asset.Color;
                    row.insertCell().textContent = asset.Size;
                    row.insertCell().textContent = asset.Owner;
                    row.insertCell().textContent = asset.AppraisedValue;
                });
                showStatus(allAssetsStatus, `Successfully loaded ${data.assets.length} assets.`, 'success');
            } else {
                showStatus(allAssetsStatus, 'No assets found on the ledger.', 'info');
            }

        } catch (error) {
            showStatus(allAssetsStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Fetch all assets error:', error);
        }
    }

    // Event Listeners

    // Init Ledger
    initLedgerBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to initialize the ledger? This will remove all existing assets and reset it.')) {
            return;
        }
        showStatus(initLedgerStatus, 'Initializing ledger...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/init-ledger`, {
                method: 'POST',
            });
            const data = await response.json();

            if (response.ok) {
                showStatus(initLedgerStatus, data.message, 'success');
                fetchAllAssets(); // Refresh assets after init
            } else {
                showStatus(initLedgerStatus, `Error: ${data.message} (${data.details || ''})`, 'error');
            }
        } catch (error) {
            showStatus(initLedgerStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Init ledger error:', error);
        }
    });

    // Refresh All Assets
    refreshAssetsBtn.addEventListener('click', fetchAllAssets);

    // Create Asset
    createAssetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideStatus(createAssetStatus);

        const asset = {
            id: document.getElementById('createAssetId').value,
            color: document.getElementById('createAssetColor').value,
            size: parseInt(document.getElementById('createAssetSize').value, 10),
            owner: document.getElementById('createAssetOwner').value,
            appraisedValue: parseInt(document.getElementById('createAssetValue').value, 10), // Convert to number
        };

        if (isNaN(asset.appraisedValue)) {
            showStatus(createAssetStatus, 'Appraised Value must be a number.', 'error');
            return;
        }

        showStatus(createAssetStatus, 'Creating asset...', 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/assets`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(asset),
            });
            const data = await response.json();

            if (response.ok) {
                showStatus(createAssetStatus, data.message, 'success');
                createAssetForm.reset(); // Clear form
                fetchAllAssets(); // Refresh assets
            } else {
                showStatus(createAssetStatus, `Error: ${data.message} (${data.details || ''})`, 'error');
            }
        } catch (error) {
            showStatus(createAssetStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Create asset error:', error);
        }
    });

    // Query Asset by ID
    queryAssetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideStatus(queryAssetStatus);
        queryAssetResult.textContent = '';

        const assetId = document.getElementById('queryAssetId').value;
        if (!assetId) {
            showStatus(queryAssetStatus, 'Please enter an Asset ID.', 'error');
            return;
        }

        showStatus(queryAssetStatus, `Querying asset ${assetId}...`, 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/assets/${assetId}`);
            const data = await response.json();

            if (response.ok) {
                showStatus(queryAssetStatus, `Successfully queried asset ${assetId}.`, 'success');
                queryAssetResult.textContent = JSON.stringify(data, null, 2); // Pretty print JSON
            } else {
                showStatus(queryAssetStatus, `Error: ${data.message || 'Asset not found'} (${data.details || ''})`, 'error');
                queryAssetResult.textContent = JSON.stringify(data, null, 2);
            }
        } catch (error) {
            showStatus(queryAssetStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Query asset error:', error);
        }
    });

    // Transfer Asset
    transferAssetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideStatus(transferAssetStatus);

        const assetId = document.getElementById('transferAssetId').value;
        const newOwner = document.getElementById('transferNewOwner').value;

        if (!assetId || !newOwner) {
            showStatus(transferAssetStatus, 'Please enter both Asset ID and New Owner.', 'error');
            return;
        }

        showStatus(transferAssetStatus, `Transferring asset ${assetId} to ${newOwner}...`, 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/assets/transfer`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: assetId, newOwner: newOwner }),
            });
            const data = await response.json();

            if (response.ok) {
                showStatus(transferAssetStatus, `${data.message} (TxID: ${data.transactionId}). Check server console for commit status.`, 'success');
                transferAssetForm.reset();
                // Assets will be updated on refresh, this is async, so not immediately visible
            } else {
                showStatus(transferAssetStatus, `Error: ${data.message} (${data.details || ''})`, 'error');
            }
        } catch (error) {
            showStatus(transferAssetStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Transfer asset error:', error);
        }
    });

    // Error Test
    errorTestBtn.addEventListener('click', async () => {
        hideStatus(errorTestStatus);
        errorTestResult.textContent = '';

        showStatus(errorTestStatus, 'Triggering error test...', 'info');

        try {
            const response = await fetch(`${API_BASE_URL}/error-test`, {
                method: 'POST',
            });
            const data = await response.json();

            // This endpoint is expected to fail with a non-200 status
            if (!response.ok) {
                showStatus(errorTestStatus, `Error Test Result: ${data.message} (Status: ${response.status})`, 'error');
                errorTestResult.textContent = JSON.stringify(data, null, 2);
            } else {
                // Unexpected success, though unlikely for this endpoint
                showStatus(errorTestStatus, 'Error test unexpectedly succeeded!', 'success');
                errorTestResult.textContent = JSON.stringify(data, null, 2);
            }
        } catch (error) {
            showStatus(errorTestStatus, `Network error: ${error.message}. Ensure your Go middleware is running on port 8081.`, 'error');
            console.error('Error test network error:', error);
        }
    });

    // Initial load: Fetch all assets when the page loads
    fetchAllAssets();
});
