// --- CSRF Token Setup ---
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
const csrftoken = getCookie('csrftoken');

// --- UI Display Functions ---

function showLoadingState(type) {
    const loadingContainer = document.getElementById('loading-container');
    const submitBtn = document.getElementById(`submit-btn-${type}`);
    
    loadingContainer.classList.remove('hidden');
    loadingContainer.innerHTML = `
        <div class="bg-white/80 backdrop-blur-lg rounded-3xl p-12 shadow-2xl text-center">
            <div class="mb-6">
                <div class="relative w-24 h-24 mx-auto">
                    <div class="absolute inset-0 border-4 border-blue-200 rounded-full"></div>
                    <div class="absolute inset-0 border-4 border-blue-600 rounded-full border-t-transparent animate-spin"></div>
                </div>
            </div>
            <h3 class="text-2xl font-bold text-gray-800 mb-4">AI Analysis in Progress</h3>
            <p class="text-gray-600">Contacting server and analyzing with ML model...</p>
        </div>`;
    
    if(submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<div class="flex items-center justify-center space-x-2"><div class="w-6 h-6 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Analyzing...</span></div>`;
    }
}

function displayResults(type, result) {
    const resultContainer = document.getElementById('result-container');
    resultContainer.classList.remove('hidden');

    let fraudScoreForDisplay, fraudScoreForSVG, scoreLabel, scoreLabelBg, strokeColor, scoreColorClass;

    // Create a more dramatic output based on the binary prediction
    if (result.prediction === 1) { // Phishing
        fraudScoreForDisplay = '99%';
        fraudScoreForSVG = 99; // For the circular progress bar
        scoreLabel = 'PHISHING DETECTED';
        scoreLabelBg = 'bg-red-600';
        strokeColor = '#dc2626'; // Red-600
        scoreColorClass = 'text-red-600 animate-pulse';
    } else { // Legitimate
        fraudScoreForDisplay = '1%';
        fraudScoreForSVG = 1;
        scoreLabel = 'SAFE';
        scoreLabelBg = 'bg-green-500';
        strokeColor = '#22c55e'; // Green-500
        scoreColorClass = 'text-green-500';
    }

    resultContainer.innerHTML = `
        <div class="bg-white/90 backdrop-blur-lg rounded-3xl shadow-2xl overflow-hidden border border-white/50">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 p-6"><h2 class="text-3xl font-bold text-white flex items-center"><svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>Security Analysis Report</h2></div>
            <div class="p-8">
                <div class="grid md:grid-cols-2 gap-8 mb-8">
                    <div><h3 class="text-lg font-semibold text-gray-700 mb-2">Analyzed Target:</h3><p class="text-gray-600 break-all bg-gray-50 p-4 rounded-xl">${result.url}</p></div>
                    <div class="text-center">
                        <div class="relative inline-block">
                            <div class="w-32 h-32 mx-auto mb-4 relative">
                                <svg class="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                                    <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#e5e7eb" stroke-width="3"></path>
                                    <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="${strokeColor}" stroke-width="3" stroke-dasharray="${fraudScoreForSVG}, 100" class="transition-all duration-1000"></path>
                                </svg>
                                <div class="absolute inset-0 flex items-center justify-center"><span class="text-3xl font-bold ${scoreColorClass}">${fraudScoreForDisplay}</span></div>
                            </div>
                        </div>
                        <div class="inline-block px-6 py-2 rounded-full font-bold text-white ${scoreLabelBg} text-lg">${scoreLabel}</div>
                    </div>
                </div>
                <div class="space-y-6">
                    <div class="bg-gray-50 rounded-2xl p-6"><h4 class="font-bold text-gray-800 mb-3 flex items-center"><svg class="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>Detailed Analysis</h4><p class="text-gray-700 leading-relaxed">${result.analysis_details}</p></div>
                    <div class="text-center pt-4"><p class="text-sm text-gray-500">Analysis completed on ${new Date(result.timestamp).toLocaleString()}</p></div>
                </div>
            </div>
        </div>`;
}

function displayError(error) {
    const errorContainer = document.getElementById('error-container');
    errorContainer.classList.remove('hidden');
    errorContainer.innerHTML = `
        <div class="bg-red-50 border-l-4 border-red-500 p-6 rounded-r-2xl mb-8">
            <div class="flex items-center">
                <svg class="w-6 h-6 text-red-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <p class="text-red-700 font-medium"><strong>Analysis Failed:</strong> ${error}</p>
            </div>
        </div>`;
}

function resetUI(type) {
    document.getElementById('error-container').classList.add('hidden');
    document.getElementById('loading-container').classList.add('hidden');
    document.getElementById('result-container').classList.add('hidden');

    const submitBtn = document.getElementById(`submit-btn-${type}`);
    if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<div class="flex items-center justify-center space-x-2"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg><span>Start Analysis</span></div>`;
    }
}


// --- API Communication ---

async function handleAnalyze(event, type) {
    event.preventDefault();
    resetUI(type);
    showLoadingState(type);

    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    const apiEndpoint = type === 'website' ? '/api/analyze/website/' : '/api/analyze/mobile/';

    try {
        const response = await fetch(apiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `Server responded with status ${response.status}`);
        }

        const result = await response.json();
        document.getElementById('loading-container').classList.add('hidden');
        displayResults(type, result);

    } catch (error) {
        console.error('Fetch Error:', error);
        document.getElementById('loading-container').classList.add('hidden');
        displayError(`An error occurred: ${error.message}`);
    } finally {
        const submitBtn = document.getElementById(`submit-btn-${type}`);
        if(submitBtn){
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<div class="flex items-center justify-center space-x-2"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg><span>Start Analysis</span></div>`;
        }
    }
}


// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', () => {
    const websiteForm = document.getElementById('form-website');
    if (websiteForm) {
        websiteForm.addEventListener('submit', (e) => handleAnalyze(e, 'website'));
    }

    const mobileForm = document.getElementById('form-mobile-app');
    if (mobileForm) {
        mobileForm.addEventListener('submit', (e) => handleAnalyze(e, 'mobile-app'));
    }
});

