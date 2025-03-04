document.addEventListener("DOMContentLoaded", function () {
    const adminLoginForm = document.getElementById("admin-login-form");

    if (adminLoginForm) {
        adminLoginForm.addEventListener("submit", async function (event) {
            event.preventDefault();

            const username = document.getElementById("admin-username").value.trim();
            const password = document.getElementById("admin-password").value.trim();
            const errorMessage = document.getElementById("admin-login-error");

            // Reset error message
            errorMessage.textContent = "";

            // Basic validation
            if (!username || !password) {
                errorMessage.textContent = "Username and password are required.";
                return;
            }

            try {
                // Send login request to server
                const response = await fetch("/admin/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password }),
                });
                console.log("Sending login request:", { username, password });
                const data = await response.json();

                if (response.ok) {
                    // Redirect to admin dashboard on success
                    window.location.href = "/admin/dashboard";
                } else {
                    errorMessage.textContent = data.message || "Invalid credentials.";
                }
            } catch (error) {
                console.error("Admin login request failed:", error);
                errorMessage.textContent = "An error occurred. Please try again.";
            }
        });
    }
});
