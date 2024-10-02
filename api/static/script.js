const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileSelect = document.getElementById('file-select');
const progress = document.getElementById('progress');
const progressBar = document.getElementById('progress-bar');
const downloadLink = document.getElementById('download-link');
const downloadA = document.getElementById('download-a');
const message = document.getElementById('message');

// Prevent default behaviors
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
    document.body.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults (e) {
    e.preventDefault();
    e.stopPropagation();
}

// Highlight drop zone when item is dragged over it
['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
        dropZone.classList.add('dragover');
    }, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
        dropZone.classList.remove('dragover');
    }, false);
});

// Handle dropped files
dropZone.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;

    if (files.length) {
        uploadFile(files[0]);
    }
}

// Handle file selection via button
fileSelect.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
        uploadFile(fileInput.files[0]);
    }
});

function uploadFile(file) {
    // Reset UI
    progress.hidden = false;
    progressBar.style.width = '0%';
    downloadLink.hidden = true;
    message.innerText = '';

    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/v1/upload_csv', true);
    xhr.setRequestHeader('Accept', 'text/csv');

    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressBar.style.width = percentComplete + '%';
        }
    });

    xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                // Create a Blob from the response
                const blob = new Blob([xhr.response], { type: 'text/csv' });
                const url = window.URL.createObjectURL(blob);
                downloadA.href = url;
                downloadA.download = 'enhanced_report.csv';
                downloadLink.hidden = false;
                progress.hidden = true;
                message.innerText = 'Report processed successfully!';
            } else {
                progress.hidden = true;
                message.innerText = `Error: ${xhr.statusText}`;
            }
        }
    };

    xhr.send(formData);
}

