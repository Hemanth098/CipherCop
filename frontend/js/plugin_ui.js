// This function runs when the popup HTML has been fully loaded.
$(document).ready(function() {
    // Add a click listener to the analyze button
    $('#analyze-button').on('click', function() {
        
        // 1. Hide the initial button view and show the loading spinner
        $('#initial-view').hide();
        $('#loading').show();

        // 2. Get the currently active tab to find its URL
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            // Handle cases where the URL is not accessible (e.g., chrome:// pages)
            if (!tabs || !tabs[0] || !tabs[0].url || !tabs[0].url.startsWith('http')) {
                const errorData = {
                    fraudScore: 'N/A',
                    category: 'Error',
                    analysisDetails: 'Cannot analyze this page.<br>Try a standard website (http or https).'
                };
                updateUI(errorData);
                // Hide loader and show the results view
                $('#loading').hide();
                $('#results-view').show();
                return;
            }
            
            const currentUrl = tabs[0].url;

            // 3. Send the URL to YOUR Django backend for analysis
            fetch('http://127.0.0.1:8000/api/analyze-website/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: currentUrl }), // Use 'url' key for the plugin
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Server returned an error.');
                }
                return response.json();
            })
            .then(data => {
                // 4a. On success, update the UI with the results from Django
                updateUI(data);
            })
            .catch(error => {
                // 4b. On failure (e.g., Django server is down), display an error
                console.error('Error:', error);
                const errorData = {
                    fraudScore: 'ERR',
                    category: 'Error',
                    analysisDetails: 'Could not connect to the analysis server.<br>Please ensure your Django server is running.'
                };
                updateUI(errorData);
            })
            .finally(() => {
                // 5. CRITICAL STEP: No matter what, hide the loader and show the final results view
                $('#loading').hide();
                $('#results-view').show();
            });
        });
    });
});

// This function updates all the UI elements based on the data from Django
function updateUI(data) {
    const score = data.fraudScore;
    const category = data.category;
    const details = data.analysisDetails;

    const scoreCircle = $('#score-circle');
    const scoreText = $('#site-score');
    const statusMessage = $('#site-msg');
    const featuresDiv = $('#features');

    scoreText.text(typeof score === 'number' ? `${score}%` : score);

    // Clear previous color classes
    scoreCircle.removeClass('safe warning danger');
    statusMessage.removeClass('safe warning danger');

    // Set new colors and status message based on the category from the backend
    if (category === 'Phishing' || category === 'Error') {
        scoreCircle.addClass('danger');
        statusMessage.addClass('danger');
        statusMessage.html("🛡️ Warning! This site is potentially unsafe.");
    } else if (category.includes('Might Cause Phishing')) {
        scoreCircle.addClass('warning');
        statusMessage.addClass('warning');
        statusMessage.html("🛡️ Caution Advised. This site has some warning signs.");
    } else {
        scoreCircle.addClass('safe');
        statusMessage.addClass('safe');
        statusMessage.html("🛡️ This website appears to be safe.");
    }

    // Update the features list from the analysisDetails string
    featuresDiv.empty();
    if (details) {
        const detailLines = details.split('<br>');
        detailLines.forEach(line => {
            if (line.trim()) {
                let featureClass = 'feature-safe';
                if (line.toLowerCase().includes('phishing') || category === 'Error') {
                    featureClass = 'feature-danger';
                } else if (line.toLowerCase().includes('threshold')) {
                    featureClass = 'feature-warning';
                }
                featuresDiv.append(`<div class="feature-item ${featureClass}">${line}</div>`);
            }
        });
    }
}

