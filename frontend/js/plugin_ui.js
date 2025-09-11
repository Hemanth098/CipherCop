// This function runs when the popup HTML has been fully loaded.
$(document).ready(function() {
    // Load history from storage as soon as the popup opens
    loadHistory();

    // Add a click listener to the 'Analyze Current Site' button
    $('#analyze-current-button').on('click', function() {
        // Get the currently active tab to find its URL
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (!tabs || !tabs[0] || !tabs[0].url || !tabs[0].url.startsWith('http')) {
                handleError('Cannot analyze this page. Try a standard website (http or https).');
                return;
            }
            performAnalysis(tabs[0].url);
        });
    });

    // Add a click listener to the new button for manual URL input
    $('#analyze-url-button').on('click', function() {
        const url = $('#url-input').val().trim();
        if (!url || !url.startsWith('http')) {
            alert('Please enter a valid URL starting with http or https.');
            return;
        }
        performAnalysis(url);
    });

    // Add click listener to clear history button
    $('#clear-history-button').on('click', function() {
        // Ask for confirmation
        if (confirm('Are you sure you want to clear all analysis history?')) {
            chrome.storage.local.set({ analysisHistory: [] }, function() {
                renderHistory([]); // Re-render the now-empty history
            });
        }
    });
});

// Central function to handle the analysis process for a given URL
function performAnalysis(url) {
    // 1. Switch to the analyzer tab, hide initial view, and show loader
    new bootstrap.Tab($('#analyzer-tab')).show();
    $('#initial-view').hide();
    $('#results-view').hide();
    $('#loading').show();

    // 2. Send the URL to YOUR Django backend
    fetch('http://127.0.0.1:8000/api/analyze-website/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { 
                throw new Error(err.error || 'Server returned an error.');
            });
        }
        return response.json();
    })
    .then(data => {
        // 3a. On success, update UI and save to history
        updateUI(data);
        saveToHistory(url, data);
    })
    .catch(error => {
        // 3b. On failure, display an error and save to history
        console.error('Error:', error);
        const errorData = {
            fraudScore: 'ERR',
            category: 'Error',
            analysisDetails: `Could not connect to the analysis server.<br><i>${error.message}</i>`
        };
        updateUI(errorData);
        saveToHistory(url, errorData);
    })
    .finally(() => {
        // 4. No matter what, hide loader and show results
        $('#loading').hide();
        $('#results-view').show();
    });
}

// Handles non-fetch related errors (e.g., invalid tab)
function handleError(errorMessage) {
    new bootstrap.Tab($('#analyzer-tab')).show();
    const errorData = {
        fraudScore: 'N/A',
        category: 'Error',
        analysisDetails: errorMessage
    };
    updateUI(errorData);
    $('#initial-view').hide();
    $('#loading').hide();
    $('#results-view').show();
}

// Updates all the UI elements in the "Analyzer" tab based on data
// This function updates all the UI elements based on the data from Django
function updateUI(data) {
    const score = data.fraudScore;
    const category = data.category;
    const details = data.analysisDetails;

    const scoreCircle = $('#score-circle');
    const scoreText = $('#site-score');
    const statusMessage = $('#site-msg');
    const featuresDiv = $('#features');

    // Display the score, whether it's a number or a string like 'ERR'
    scoreText.text(typeof score === 'number' ? `${score}%` : score);

    // --- REVISED LOGIC ---
    // Clear previous classes first
    scoreCircle.removeClass('safe warning danger');
    statusMessage.removeClass('safe warning danger');

    let statusClass = 'safe'; // Default class
    let message = "🛡️ This website appears to be safe."; // Default message

    // Determine status based on the numerical score
    if (typeof score === 'number') {
        if (score >= 75) {
            statusClass = 'danger';
            message = "🛡️ Warning! This site is potentially unsafe.";
        } else if (score >= 40) {
            statusClass = 'warning';
            message = "🛡️ Caution Advised. This site has some warning signs.";
        } else {
            statusClass = 'safe';
            message = "🛡️ This website appears to be safe.";
        }
    } else if (category === 'Error') {
        // Handle non-numeric scores for error cases
        statusClass = 'danger';
        message = "🛡️ Analysis Failed";
    }

    // Apply the determined class and message
    scoreCircle.addClass(statusClass);
    statusMessage.addClass(statusClass);
    statusMessage.html(message);
    
    // --- END OF REVISED LOGIC ---

    // Update the features list from the analysisDetails string
    featuresDiv.empty();
    if (details) {
        const detailLines = details.split('<br>');
        detailLines.forEach(line => {
            if (line.trim()) {
                // Use the already determined statusClass for feature coloring
                let featureClass = 'feature-safe';
                if (statusClass === 'danger') {
                    featureClass = 'feature-danger';
                } else if (statusClass === 'warning') {
                    featureClass = 'feature-warning';
                }
                featuresDiv.append(`<div class="feature-item ${featureClass}">${line}</div>`);
            }
        });
    }
}

// --- History Management Functions ---

function saveToHistory(url, resultData) {
    chrome.storage.local.get({ analysisHistory: [] }, function(data) {
        const history = data.analysisHistory;
        const newEntry = {
            url: url,
            score: resultData.fraudScore,
            category: resultData.category,
            timestamp: new Date().toISOString()
        };
        // Add new entry to the beginning of the array
        history.unshift(newEntry);
        // Keep only the latest 20 entries
        const trimmedHistory = history.slice(0, 20);
        chrome.storage.local.set({ analysisHistory: trimmedHistory }, function() {
            // Re-render history list with the new data
            renderHistory(trimmedHistory);
        });
    });
}

function loadHistory() {
    chrome.storage.local.get({ analysisHistory: [] }, function(data) {
        renderHistory(data.analysisHistory);
    });
}

function renderHistory(history) {
    const historyList = $('#history-list');
    const emptyMsg = $('#history-empty');
    const clearBtn = $('#clear-history-button');
    historyList.empty();

    if (history.length === 0) {
        emptyMsg.show();
        clearBtn.hide();
    } else {
        emptyMsg.hide();
        clearBtn.show();
        history.forEach(item => {
            let statusClass = 'safe';
            if (item.category === 'Error' || item.category === 'Phishing') {
                statusClass = 'danger';
            } else if (item.category.includes('Might Cause Phishing')) {
                statusClass = 'warning';
            }
            
            const scoreDisplay = typeof item.score === 'number' ? `${item.score}%` : item.score;
            const timeAgo = new Date(item.timestamp).toLocaleString();

            const historyItemHTML = `
                <div class="history-item ${statusClass}">
                    <div class="history-url">${item.url}</div>
                    <div class="history-details">
                        <strong>${item.category} (${scoreDisplay})</strong> - <span>${timeAgo}</span>
                    </div>
                </div>
            `;
            historyList.append(historyItemHTML);
        });
    }
}