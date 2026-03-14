console.debug("credupdate: loaded");

// Counter for pending changes
let pendingChangesCount = 0;

// Endpoints that modify credentials (add/remove operations)
const MODIFYING_ENDPOINTS = [
    "/ui/api/finish_passkey",
    "/ui/api/remove_passkey",
    "/ui/api/remove_alt_creds",
    "/ui/api/remove_totp",
    "/ui/api/remove_unixcred",
    "/ui/api/remove_ssh_publickey",
    "/ui/reset/add_password",
    "/ui/reset/set_unixcred",
    "/ui/reset/add_totp",
    "/ui/api/add_totp",
    "/ui/reset/add_ssh_publickey",
];

function updateSaveButton() {
    const saveBtn = document.getElementById("save-changes-btn");
    if (saveBtn) {
        const baseText = "Save Changes";
        if (pendingChangesCount > 0) {
            saveBtn.textContent = `${baseText} (${pendingChangesCount})`;
        } else {
            saveBtn.textContent = baseText;
        }
    }
}

function incrementPendingChanges() {
    pendingChangesCount++;
    updateSaveButton();
    console.debug(`credupdate: pending changes = ${pendingChangesCount}`);
}

function resetPendingChanges() {
    pendingChangesCount = 0;
    updateSaveButton();
    console.debug("credupdate: pending changes reset to 0");
}

window.resetPendingChangesCount = resetPendingChanges;

// Makes the password form interactive (e.g. shows when passwords don't match)
function setupInteractivePwdFormListeners() {
    const new_pwd = document.getElementById("new-password");
    const new_pwd_check = document.getElementById("new-password-check");
    const pwd_submit = document.getElementById("password-submit");

    function markPwdCheckValid() {
        new_pwd_check.classList.remove("is-invalid");
        new_pwd_check.classList.add("is-valid");
        pwd_submit.disabled = false;
    }

    function markPwdCheckInvalid() {
        new_pwd_check.classList.add("is-invalid");
        new_pwd_check.classList.remove("is-valid");
        pwd_submit.disabled = true;
    }

    new_pwd.addEventListener("input", () => {
        // Don't mark invalid if user didn't fill in the confirmation box yet
        // Also KeepassXC with autocomplete likes to fire off input events when
        // both inputs are empty.
        if (new_pwd_check.value !== "") {
            if (new_pwd.value === new_pwd_check.value) {
                markPwdCheckValid();
            } else {
                markPwdCheckInvalid();
            }
        }
        new_pwd.classList.remove("is-invalid");
    });

    new_pwd_check.addEventListener("input", () => {
        // No point in updating the status if confirmation box is empty
        if (new_pwd_check.value === "") return;
        if (new_pwd_check.value === new_pwd.value) {
            markPwdCheckValid();
        } else {
            markPwdCheckInvalid();
        }
    });
}

window.stillSwapFailureResponse = function (event) {
    if (event.detail.xhr.status === 422 || event.detail.xhr.status === 500) {
        console.debug(`Got HTTP/${event.detail.xhr.status}, still swapping failure response`);
        event.detail.shouldSwap = true;
        event.detail.isError = false;
    }
};

function onPasskeyCreated(assertion) {
    try {
        console.log(assertion);
        let creationData = {};

        creationData.id = assertion.id;
        creationData.rawId = Base64.fromUint8Array(new Uint8Array(assertion.rawId));
        creationData.response = {};
        creationData.response.attestationObject = Base64.fromUint8Array(
            new Uint8Array(assertion.response.attestationObject),
        );
        creationData.response.clientDataJSON = Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON));
        creationData.type = assertion.type;
        creationData.extensions = assertion.getClientExtensionResults();
        creationData.extensions.uvm = undefined;

        // Put the passkey creation data into the form for submission
        document.getElementById("passkey-create-data").value = JSON.stringify(creationData);

        // Make the name input visible and hide the "Begin Passkey Enrollment" button
        document.getElementById("passkeyNamingSafariPre").classList.add("d-none");
        document.getElementById("passkeyNamingForm").classList.remove("d-none");
        document.getElementById("passkeyNamingSubmitBtn").classList.remove("d-none");
    } catch (e) {
        console.log(e);
        if (
            confirm(
                "Failed to encode your new passkey's data for transmission, confirm to reload this page.\nReport this issue if it keeps occurring.",
            )
        ) {
            window.location.reload();
        }
    }
}

function startPasskeyEnrollment() {
    try {
        const data_elem = document.getElementById("data");
        const credentialRequestOptions = JSON.parse(data_elem.textContent);
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(
            credentialRequestOptions.publicKey.challenge,
        );
        credentialRequestOptions.publicKey.user.id = Base64.toUint8Array(credentialRequestOptions.publicKey.user.id);

        console.log(credentialRequestOptions);
        navigator.credentials.create({ publicKey: credentialRequestOptions.publicKey }).then(
            (assertion) => {
                onPasskeyCreated(assertion);
            },
            (reason) => {
                alert(`Passkey creation failed ${reason.toString()}`);
                console.log(`Passkey creation failed: ${reason.toString()}`);
            },
        );
    } catch (e) {
        console.log(`Failed to initialize passkey creation: ${e}`);
        if (
            confirm(
                "Failed to initialize passkey creation, confirm to reload this page.\nReport this issue if it keeps occurring.",
            )
        ) {
            window.location.reload();
        }
    }
}

function setupPasskeyNamingSafariButton() {
    document.getElementById("passkeyNamingSafariBtn").addEventListener("click", startPasskeyEnrollment);
}

function setupSubmitBtnVisibility() {
    document.getElementById("passkey-label")?.addEventListener("input", updateSubmitButtonVisibility);
}

function updateSubmitButtonVisibility(event) {
    const submitButton = document.getElementById("passkeyNamingSubmitBtn");
    submitButton.disabled = event.value === "";
}

function beforeUnloadHandler(event) {
    console.debug("credupdate: beforeUnloadHandler");
    const confirmationMessage = "Unsaved changes will be lost.";

    (event || window.event).returnValue = confirmationMessage;
    return confirmationMessage;
}

window.removeBeforeUnloadHandler = function () {
    console.debug("credupdate: removeBeforeUnloadHandler");
    window.removeEventListener("beforeunload", beforeUnloadHandler);
};

(function () {
    console.debug("credupdate: init");
    document.body.addEventListener("addPasswordSwapped", () => {
        setupInteractivePwdFormListeners();
    });
    document.body.addEventListener("addPasskeySwapped", () => {
        setupPasskeyNamingSafariButton();
        startPasskeyEnrollment();
        setupSubmitBtnVisibility();
    });
    window.addEventListener("beforeunload", beforeUnloadHandler);

    // Track HTMX requests that modify credentials
    document.body.addEventListener("htmx:beforeRequest", (event) => {
        const path = event.detail.pathInfo.requestPath;
        // Check if this is a modifying endpoint
        if (MODIFYING_ENDPOINTS.some((endpoint) => path.startsWith(endpoint))) {
            event.detail.pendingChangesIncrement = true;
        }
    });

    document.body.addEventListener("htmx:afterRequest", (event) => {
        const path = event.detail.pathInfo.requestPath;
        // Only increment if the request was successful and it was a modifying endpoint
        if (
            event.detail.successful &&
            event.detail.pendingChangesIncrement &&
            MODIFYING_ENDPOINTS.some((endpoint) => path.startsWith(endpoint))
        ) {
            incrementPendingChanges();
        }
    });

    // Update the save button on page load
    updateSaveButton();
})();
