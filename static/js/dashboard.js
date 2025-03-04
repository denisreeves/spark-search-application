// Global Variables for Filter Logic
let originalColumns = [];
let availableColumns = [];
let selectedFilters = [];
let numericMaxValues = {};  // Will hold maximum values for numeric columns

// File Handling DOM References
const fileDropzone = document.getElementById("file-dropzone");
const fileInput = document.getElementById("file-upload");
const browseBtn = document.getElementById("browse-btn");
const uploadBtn = document.getElementById("upload-btn");

// Sidebar Toggle Functionality
const sidebar = document.getElementById("sidebar");
const sidebarToggle = document.getElementById("sidebar-toggle");
if (sidebarToggle) {
  sidebarToggle.addEventListener("click", function(e) {
    e.stopPropagation();
    sidebar.classList.toggle("minimized");
  });
}

// DRAG AND DROP SETUP
if (fileDropzone && fileInput) {
  fileDropzone.addEventListener("click", () => {
    fileInput.click();
  });
  ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
    fileDropzone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
    });
  });
  fileDropzone.addEventListener("dragover", () => {
    fileDropzone.classList.add("dragover");
  });
  fileDropzone.addEventListener("dragleave", () => {
    fileDropzone.classList.remove("dragover");
  });
  fileDropzone.addEventListener("drop", e => {
    fileDropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      e.dataTransfer.clearData();
    }
  });
}

// BROWSE BUTTON SETUP
if (browseBtn && fileInput) {
  browseBtn.addEventListener("click", () => {
    fileInput.click();
  });
}

// When a file is selected, start the loading bar animation then upload
if (fileInput) {
  fileInput.addEventListener("change", function() {
    if (!fileInput.files.length) return;
    startLoadingBar();
  });
}

// Simulate loading bar animation then trigger file upload
function startLoadingBar() {
  const loadingContainer = document.getElementById("loading-bar-container");
  const loadingBar = document.getElementById("loading-bar");
  if (!loadingContainer || !loadingBar) return;
  loadingContainer.style.display = "block";
  loadingBar.style.width = "0%";
  let progress = 0;
  const interval = setInterval(() => {
    progress += 5;
    loadingBar.style.width = progress + "%";
    if (progress >= 100) {
      clearInterval(interval);
      uploadFile();
    }
  }, 100);
}

// Upload file via fetch to /upload
function uploadFile() {
  if (!fileInput.files.length) {
    displayMessage("Please select a file to upload.", "error");
    return;
  }
  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);
  fetch("/upload", {
    method: "POST",
    body: formData
  })
  .then(response => {
    if (!response.ok) throw new Error("Network response was not ok");
    return response.json();
  })
  .then(data => {
    if (data.status === "success") {
      displayMessage("File uploaded successfully: " + data.message, "success");
      originalColumns = data.columns.slice();
      availableColumns = data.columns.slice();
      selectedFilters = [];
      // Save numeric max values if provided
      numericMaxValues = data.numericMax || {};
      
      updateDropdownHeader();
      populateDropdown();
      clearSelectedFiltersBlocks();
      // Hide upload message and show dashboard UI
      const uploadMsg = document.getElementById("upload-message");
      if (uploadMsg) uploadMsg.style.display = "none";
      const dashboardUI = document.getElementById("dashboard-ui");
      if (dashboardUI) dashboardUI.style.display = "block";
      // Hide loading bar
      const loadingContainer = document.getElementById("loading-bar-container");
      if (loadingContainer) loadingContainer.style.display = "none";
      // Update upload info in sidebar
      updateUploadInfo(file, data.message);
    } else {
      displayMessage("Error: " + data.message, "error");
    }
  })
  .catch(error => {
    console.error(error);
    displayMessage("Error uploading file: " + error.message, "error");
  });
}

// Update upload info in sidebar
function updateUploadInfo(file, uploadMessage) {
  const uploadInfoDiv = document.getElementById("upload-info");
  if (uploadInfoDiv) {
    const fileName = file.name;
    const fileSize = (file.size / 1024).toFixed(1) + "KB";
    uploadInfoDiv.innerHTML = `
      <p class="file-name">${fileName}</p>
      <p class="file-size">${fileSize}</p>
      <p class="upload-success">✅ ${uploadMessage}</p>
    `;
    uploadInfoDiv.style.display = "block";
  }
}

// -------------- Dropdown & Filter Logic --------------
const dropdownHeader = document.getElementById("dropdown-header");
const dropdownOptions = document.getElementById("dropdown-options");
const dropdownPlaceholder = document.getElementById("dropdown-placeholder");
const dropdownSelected = document.getElementById("dropdown-selected");

if (dropdownHeader) {
  dropdownHeader.addEventListener("click", function(e) {
    e.stopPropagation();
    toggleDropdown();
  });
}
function toggleDropdown(forceClose) {
  if (!dropdownOptions) return;
  if (forceClose === true) {
    dropdownOptions.classList.remove("show");
  } else {
    dropdownOptions.classList.toggle("show");
  }
}
window.addEventListener("click", function() {
  toggleDropdown(true);
});
function populateDropdown() {
  if (!dropdownOptions) return;
  dropdownOptions.innerHTML = "";
  availableColumns.forEach(column => {
    const option = document.createElement("div");
    option.className = "dropdown-option";
    option.textContent = column;
    option.dataset.value = column;
    option.addEventListener("click", e => {
      e.stopPropagation();
      selectFilter(column);
      toggleDropdown(false);
    });
    dropdownOptions.appendChild(option);
  });
}
function updateDropdownHeader() {
  if (!dropdownPlaceholder || !dropdownSelected) return;
  dropdownSelected.innerHTML = "";
  if (selectedFilters.length === 0) {
    dropdownPlaceholder.style.display = "inline";
  } else {
    dropdownPlaceholder.style.display = "none";
    selectedFilters.forEach(column => {
      const tag = document.createElement("span");
      tag.className = "dropdown-tag";
      tag.textContent = column;
      const removeBtn = document.createElement("span");
      removeBtn.className = "tag-remove";
      removeBtn.textContent = " x";
      removeBtn.addEventListener("click", e => {
        e.stopPropagation();
        removeFilter(column);
      });
      tag.appendChild(removeBtn);
      dropdownSelected.appendChild(tag);
    });
  }
}
function selectFilter(column) {
  if (!selectedFilters.includes(column)) {
    selectedFilters.push(column);
    availableColumns = availableColumns.filter(col => col !== column);
    updateDropdownHeader();
    populateDropdown();
    addFilterBlock(column);
  }
}
function removeFilter(column) {
  selectedFilters = selectedFilters.filter(col => col !== column);
  availableColumns = originalColumns.filter(col => !selectedFilters.includes(col));
  updateDropdownHeader();
  populateDropdown();
  removeFilterBlock(column);
}

// -------------- Filter Blocks --------------
function addFilterBlock(column) {
  const container = document.getElementById("selected-filters");
  if (!container) return;
  const block = document.createElement("div");
  block.className = "filter-block";
  block.dataset.column = column;
  const label = document.createElement("label");
  label.textContent = `Select filter type for '${column}':`;
  block.appendChild(label);
  block.appendChild(document.createElement("br"));
  const textRadio = document.createElement("input");
  textRadio.type = "radio";
  textRadio.name = `filter_type_${column}`;
  textRadio.value = "text";
  textRadio.checked = true;
  block.appendChild(textRadio);
  const textLabel = document.createElement("span");
  textLabel.textContent = " Text Search ";
  block.appendChild(textLabel);
  const rangeRadio = document.createElement("input");
  rangeRadio.type = "radio";
  rangeRadio.name = `filter_type_${column}`;
  rangeRadio.value = "range";
  block.appendChild(rangeRadio);
  const rangeLabel = document.createElement("span");
  rangeLabel.textContent = " Range Search";
  block.appendChild(rangeLabel);
  const inputDiv = document.createElement("div");
  inputDiv.className = "filter-input";
  // Default: text input
  inputDiv.innerHTML = `<input type="text" placeholder="Search by ${column}" name="text_${column}">`;
  block.appendChild(inputDiv);
  // When range radio is selected, use slider if numeric max value exists
  rangeRadio.addEventListener("change", function() {
    if (this.checked) {
      if (numericMaxValues && numericMaxValues[column] !== undefined) {
        // Create two range inputs for min and max values with dynamic max
        inputDiv.innerHTML = `
          <div>
            <label>Min: </label>
            <input type="range" name="min_${column}" min="0" max="${numericMaxValues[column]}" value="0" oninput="this.nextElementSibling.value = this.value">
            <output>0</output>
          </div>
          <div>
            <label>Max: </label>
            <input type="range" name="max_${column}" min="0" max="${numericMaxValues[column]}" value="${numericMaxValues[column]}" oninput="this.nextElementSibling.value = this.value">
            <output>${numericMaxValues[column]}</output>
          </div>
        `;
      } else {
        // Fallback to number inputs if no numeric info is available
        inputDiv.innerHTML = `<input type="number" placeholder="Min ${column}" name="min_${column}">
                              <input type="number" placeholder="Max ${column}" name="max_${column}">`;
      }
    }
  });
  textRadio.addEventListener("change", function() {
    if (this.checked) {
      inputDiv.innerHTML = `<input type="text" placeholder="Search by ${column}" name="text_${column}">`;
    }
  });
  container.appendChild(block);
}
function removeFilterBlock(column) {
  const container = document.getElementById("selected-filters");
  if (!container) return;
  const block = container.querySelector(`.filter-block[data-column="${column}"]`);
  if (block) container.removeChild(block);
}
function clearSelectedFiltersBlocks() {
  const container = document.getElementById("selected-filters");
  if (container) container.innerHTML = "";
}

// -------------- Search Button Handling --------------
const searchBtn = document.getElementById("search-btn");
if (searchBtn) {
  searchBtn.addEventListener("click", function() {
    const filters = {};
    const blocks = document.querySelectorAll("#selected-filters .filter-block");
    blocks.forEach(block => {
      const column = block.dataset.column;
      const filterType = block.querySelector(`input[name="filter_type_${column}"]:checked`).value;
      if (filterType === "text") {
        const textValue = block.querySelector(`input[name="text_${column}"]`).value;
        if (textValue) {
          filters[column] = { text: textValue };
        }
      } else if (filterType === "range") {
        // Check if slider exists (range inputs) or number inputs
        const minInput = block.querySelector(`input[name="min_${column}"]`);
        const maxInput = block.querySelector(`input[name="max_${column}"]`);
        if (minInput && maxInput && minInput.value !== "" && maxInput.value !== "") {
          filters[column] = { range: [Number(minInput.value), Number(maxInput.value)] };
        }
      }
    });
    const selectedColumns = selectedFilters.slice();
    fetch("/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filters, selectedColumns })
    })
    .then(response => {
      if (!response.ok) throw new Error("Network response was not ok");
      return response.json();
    })
    .then(data => {
      if (data.status === "success") {
        displayMessage("Displaying " + data.results.length + " records", "success");
        displayResults(data.results);
      } else {
        displayMessage("Error: " + data.message, "error");
      }
    })
    .catch(error => {
      console.error(error);
      displayMessage("Error during search: " + error.message, "error");
    });
  });
}

// -------------- Results Options Handling --------------
const fitScreenBtn = document.getElementById("fit-screen-btn");
const downloadCsvBtn = document.getElementById("download-csv-btn");
const resultsSearch = document.getElementById("results-search");
if (fitScreenBtn) {
  fitScreenBtn.addEventListener("click", function(e) {
    e.stopPropagation();
    const container = document.getElementById("results-container");
    if (container) container.classList.toggle("fullscreen");
  });
}
if (downloadCsvBtn) {
  downloadCsvBtn.addEventListener("click", function(e) {
    e.stopPropagation();
    downloadResultsAsCSV();
  });
}
if (resultsSearch) {
  resultsSearch.addEventListener("input", function() {
    filterResultsTable(this.value);
  });
}

// -------------- Display Results in Table --------------
function displayResults(results) {
  const table = document.getElementById("results-table");
  if (!table) return;
  table.innerHTML = "";
  if (!results.length) {
    table.innerHTML = "<tr><td>No results found</td></tr>";
    return;
  }
  // Create table header
  const header = document.createElement("tr");
  Object.keys(results[0]).forEach(key => {
    const th = document.createElement("th");
    th.textContent = key;
    header.appendChild(th);
  });
  table.appendChild(header);
  // Create table rows
  results.forEach(row => {
    const tr = document.createElement("tr");
    Object.values(row).forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
}

// -------------- Utility: Display Message --------------
function displayMessage(message, type) {
  const messageDiv = document.getElementById("results-message");
  if (messageDiv) {
    messageDiv.textContent = message;
    messageDiv.style.color = (type === "success" ? "green" : "red");
  } else {
    console.warn("results-message element not found. Message:", message);
  }
}

// -------------- Download CSV Functionality --------------
function downloadResultsAsCSV() {
  const table = document.getElementById("results-table");
  if (!table) return;
  let csv = [];
  for (let row of table.rows) {
    let rowData = [];
    for (let cell of row.cells) {
      rowData.push('"' + cell.textContent.replace(/"/g, '""') + '"');
    }
    csv.push(rowData.join(","));
  }
  let csvString = csv.join("\n");
  let blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
  let link = document.createElement("a");
  if (link.download !== undefined) {
    let url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", "results.csv");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
}
// -------------- Download Xlsx Functionality --------------
function downloadResultsAsCSV() {
  const table = document.getElementById("results-table");
  if (!table) return;
  let csv = [];
  for (let row of table.rows) {
    let rowData = [];
    for (let cell of row.cells) {
      rowData.push('"' + cell.textContent.replace(/"/g, '""') + '"');
    }
    csv.push(rowData.join(","));
  }
  let csvString = csv.join("\n");
  let blob = new Blob([csvString], { type: "text/xlsx;charset=utf-8;" });
  let link = document.createElement("a");
  if (link.download !== undefined) {
    let url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", "results.xlsx");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
}

// -------------- Filter Results Table --------------
function filterResultsTable(query) {
  const table = document.getElementById("results-table");
  if (!table) return;
  const rows = table.getElementsByTagName("tr");
  query = query.toLowerCase();
  for (let i = 1; i < rows.length; i++) {  // skip header row
    let cells = rows[i].getElementsByTagName("td");
    let rowContainsQuery = false;
    for (let j = 0; j < cells.length; j++) {
      if (cells[j].textContent.toLowerCase().includes(query)) {
        rowContainsQuery = true;
        break;
      }
    }
    rows[i].style.display = rowContainsQuery ? "" : "none";
  }
}
