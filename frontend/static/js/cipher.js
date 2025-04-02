document.addEventListener("DOMContentLoaded", function () {
    const encryptionMethod = document.getElementById("encryptionMethod");
    const generateIVButton = document.getElementById("generateIVButton");
    const encryptionMode = document.getElementById("encryptionMode");
    const encryptionModeContainer = document.getElementById("encryptionModeContainer");
    const encryptionIVContainer = document.getElementById("encryptionIVContainer");
    const encryptionKeyContainer = document.querySelector(".key-box");
    const decryptionKeyContainer = document.querySelector(".key-box.inner-box");
    const decryptionModeContainer = document.getElementById("decryptionModeContainer");
    const encryptionKey = document.getElementById("encryptionKey");
    const keyButtons = document.querySelector(".key-btn"); 

    // Function to handle method change logic
    function handleEncryptionMethodChange() {
        if (encryptionMethod.value === "aes" || encryptionMethod.value === "des") {
            encryptionModeContainer.classList.remove("hidden");
            decryptionModeContainer.classList.remove("hidden");
            encryptionKeyContainer.classList.remove("hidden");
            decryptionKeyContainer.classList.remove("hidden");
            encryptionKey.readOnly = false;
            encryptionKey.style.pointerEvents = 'auto';
            keyButtons.classList.remove("hidden");
        } else if (encryptionMethod.value === "otp") {
            encryptionModeContainer.classList.add("hidden");
            decryptionModeContainer.classList.add("hidden");
            encryptionKeyContainer.classList.remove("hidden");
            decryptionKeyContainer.classList.remove("hidden");
            encryptionIVContainer.classList.add("hidden");
            encryptionKey.readOnly = true;
            encryptionKey.style.pointerEvents = 'none';
            encryptionKey.value = "";
            keyButtons.classList.remove("hidden");
        } else if (encryptionMethod.value === "rsa") {
            encryptionKeyContainer.classList.add("hidden");
            decryptionKeyContainer.classList.add("hidden");
            encryptionModeContainer.classList.add("hidden");
            decryptionModeContainer.classList.add("hidden");
            encryptionIVContainer.classList.add("hidden");
            keyButtons.classList.add("hidden");
            encryptionKey.value = "";
        }
    }

    // Initialize the state based on the current value of encryptionMethod
    handleEncryptionMethodChange();

    // Event listener for encryption method change
    encryptionMethod.addEventListener("change", handleEncryptionMethodChange);

    // Handle encryption mode change
    encryptionMode.addEventListener("change", function () {
        if (this.value === "CBC" || this.value == "CFB" || this.value == "CTR") {
            encryptionIVContainer.classList.remove("hidden");
            generateIVButton.classList.remove("hidden");
        } else {
            encryptionIVContainer.classList.add("hidden");
            generateIVButton.classList.add("hidden");
        }
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const encryptionMethod = document.getElementById("encryptionMethod");
    const hiddenEncryptionMethod = document.getElementById("hiddenEncryptionMethod");
    const hiddenDecryptionMethod = document.getElementById("hiddenDecryptionMethod");

    // Set the hidden input's value based on the selected option in the dropdown
    hiddenEncryptionMethod.value = encryptionMethod.value;
    hiddenDecryptionMethod.value = encryptionMethod.value;

    // Now listen for changes to the dropdown
    encryptionMethod.addEventListener("change", function () {
        hiddenEncryptionMethod.value = this.value;
        hiddenDecryptionMethod.value = this.value;
    });
});

document.addEventListener("DOMContentLoaded", function () {
    // Get the form element by its ID
    const encryptionForm = document.getElementById("encryptionForm");

    // Attach the submit event listener to the form
    encryptionForm.addEventListener("submit", function(event) {
        event.preventDefault(); // Prevent the form from reloading the page

        // Get the CSRF token
        var csrfToken = document.querySelector('[name="csrfmiddlewaretoken"]').value;

        // Create the form data
        var formData = new FormData(encryptionForm);

        // Send the data to the server via AJAX
        fetch(encryptUrl, {
            method: "POST",
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log(data)
            // Update the page with the encrypted message
            if (data.encrypted_message) {
                document.getElementById('encryptedMessage').value = data.encrypted_message;
            } else {
                console.error("No encrypted message returned.");
            }
        })
        .catch(error => console.error('Error:', error));
    });
});

document.addEventListener("DOMContentLoaded", function () {
    // Get the form element by its ID
    const decryptionForm = document.getElementById("decryptionForm");

    // Attach the submit event listener to the form
    decryptionForm.addEventListener("submit", function(event) {
        event.preventDefault(); // Prevent the form from reloading the page

        // Get the CSRF token
        var csrfToken = document.querySelector('[name="csrfmiddlewaretoken"]').value;

        // Create the form data
        var formData = new FormData(decryptionForm);

        // Send the data to the server via AJAX
        fetch(decryptUrl, {
            method: "POST",
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log(data)
            // Update the page with the encrypted message
            if (data.decrypted_message) {
                document.getElementById('decryptedMessage').value = data.decrypted_message;
            } else {
                console.error("No decrypted message returned.");
            }
        })
        .catch(error => console.error('Error:', error));
    });
});

document.getElementById('generateKeyButton').addEventListener('click', function(event) {
    event.preventDefault();  // Prevent the form from submitting
    
    // Get the selected algorithm
    const algorithm = document.getElementById('encryptionMethod').value;
    
    // Prepare data object
    let data = {
        algorithm: algorithm  // Send the selected algorithm
    };

    // If OTP is selected, use the length of the plaintext input field
    if (algorithm === "otp") {  
        const plaintext = document.getElementById('encryptMessage').value;  
        console.log(plaintext)
        const ciphertextLength = plaintext.length;  
        console.log(ciphertextLength)
        
        if (ciphertextLength === 0) {
            alert("Please enter text to be encrypted for OTP encryption.");
            return;
        }
        data.ciphertext_length = ciphertextLength;  
    }

    // Send AJAX request to the backend (Django view)
    fetch(generateKeyUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": document.querySelector('[name=csrfmiddlewaretoken]').value,  
        },
        body: JSON.stringify(data),  
    })
    .then(response => response.json())
    .then(data => {
        if (data.key) {
            // Update the encryption key field with the generated key
            document.getElementById('encryptionKey').value = data.key;
        } else {
            alert('Error generating key: ' + data.error);
        }
    })
    .catch(error => console.error('Error:', error));
});

document.getElementById('generateIVButton').addEventListener('click', function(event) {
    event.preventDefault();  
    
    // Get the selected algorithm and mode
    const algorithm = document.getElementById('encryptionMethod').value;
    const mode = document.getElementById('encryptionMode').value;
    console.log(mode)
    console.log(algorithm)
    
    // Prepare data object for IV generation
    let ivData = {
        algorithm: algorithm,  
        mode: mode  
    };

    // Send AJAX request to the backend for IV generation
    fetch(generateIvUrl, {  
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": document.querySelector('[name=csrfmiddlewaretoken]').value,  
        },
        body: JSON.stringify(ivData),  
    })
    .then(response => response.json())
    .then(data => {
        if (data.iv) {
            // Update the IV field with the generated IV
            document.getElementById('encryptionIV').value = data.iv;
            document.getElementById('encryptionIVContainer').classList.remove('hidden');  // Show the IV input container
        } else {
            alert('Error generating IV: ' + data.error);
        }
    })
    .catch(error => console.error('Error:', error));
});


document.getElementById('copyEncryptionButton').addEventListener('click', function() {
    // Get the content of the textarea
    var encryptedMessage = document.getElementById('encryptedMessage').value;

    // Try to copy the content to the clipboard
    navigator.clipboard.writeText(encryptedMessage)
        .catch(function(err) {
            console.error("Failed to copy text: ", err);
        });
});

document.getElementById('copyDecryptionButton').addEventListener('click', function() {
    // Get the content of the textarea
    var decryptedMessage = document.getElementById('decryptedMessage').value;

    // Try to copy the content to the clipboard
    navigator.clipboard.writeText(decryptedMessage)
        .catch(function(err) {
            console.error("Failed to copy text: ", err);
        });
});

document.getElementById('copyIv').addEventListener('click', function(event) {
    event.preventDefault();  // Prevent default action (form submission or other)

    // Get the content of the IV field
    var initializationVector = document.getElementById('encryptionIV').value;
    console.log(initializationVector);  // Use console.log for debugging

    // Try to copy the content to the clipboard
    navigator.clipboard.writeText(initializationVector)
        .then(() => {
            console.log("Initialization vector copied successfully!");
        })
        .catch(function(err) {
            console.error("Failed to copy text: ", err);
        });
});

document.getElementById('copyKey').addEventListener('click', function() {
    // Get the content of the textarea
    var encryptionKey  = document.getElementById('encryptionKey').value;

    // Try to copy the content to the clipboard
    navigator.clipboard.writeText(encryptionKey)
        .catch(function(err) {
            console.error("Failed to copy text: ", err);
        });
});

document.getElementById('encryptButton').addEventListener('click', function(event) {
    // Get the values of the input fields
    const message = document.getElementById('encryptMessage').value;
    const key = document.getElementById('encryptionKey').value;
    const iv = document.getElementById('encryptionIV').value;
    const mode = document.getElementById('encryptionMode').value;
  
    // Check if message is provided
    if (!message) {
      event.preventDefault(); // Prevent form submission
      alert("Please enter a message to encrypt.");
      return; // Stop further checks
    }
  
    // Check if encryption key is provided
    if (algorithm !== "rsa" && !key) {
      event.preventDefault(); // Prevent form submission
      alert("Please enter an encryption key.");
      return; // Stop further checks
    }
  
    // Check if IV is required and provided
    if ((mode !== "ECB") && (!iv || iv.trim() === "")) {
      event.preventDefault(); // Prevent form submission
      alert("Please enter an Initialization Vector (IV).");
      return; // Stop further checks
    }
  });
  
document.getElementById('decryptButton').addEventListener('click', function(event) {
    // Get the values of the input fields
    const message = document.getElementById('decryptMessage').value;
    const key = document.getElementById('decryptionKey').value;
  
    // Check if message is provided
    if (!message) {
      event.preventDefault(); // Prevent form submission
      alert("Please enter a message to decrypt.");
      return; // Stop further checks
    }
  
    // Check if encryption key is provided
    if (algorithm !== "rsa" && !key) {
      event.preventDefault(); // Prevent form submission
      alert("Please enter a decryption key.");
      return; // Stop further checks
    }
  });