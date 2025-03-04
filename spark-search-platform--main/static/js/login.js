document.addEventListener("DOMContentLoaded", function () {
    const userLoginForm = document.getElementById("user-login-form");
    const adminLoginForm = document.getElementById("admin-login-form");

    async function handleLogin(event, formType) {
        event.preventDefault();

        const usernameField = formType === "user" ? "user-username" : "admin-username";
        const passwordField = formType === "user" ? "user-password" : "admin-password";
        const errorMessageField = formType === "user" ? "user-login-error" : "admin-login-error";

        const username = document.getElementById(usernameField).value.trim();
        const password = document.getElementById(passwordField).value.trim();
        const errorMessage = document.getElementById(errorMessageField);
        const loginEndpoint = formType === "user" ? "/login" : "/admin/login";

        errorMessage.textContent = "";
        if (!username || !password) {
            errorMessage.textContent = "Username and password are required.";
            return;
        }

        // Show loading state
        const loginButton = event.target.querySelector("button[type='submit']");
        loginButton.disabled = true;
        loginButton.textContent = "Logging in...";

        try {
            const response = await fetch(loginEndpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (response.ok) {
                console.log(`✅ Login successful! Redirecting to ${data.redirect || "/dashboard"}`);
                window.location.href = data.redirect || "/dashboard";  // Redirect to user or admin dashboard
            } else {
                errorMessage.textContent = data.message || "Invalid credentials.";
            }
        } catch (error) {
            console.error("❌ Login request failed:", error);
            errorMessage.textContent = "An error occurred. Please try again.";
        } finally {
            // Reset button state
            loginButton.disabled = false;
            loginButton.textContent = "Login";
        }
    }

    if (userLoginForm) {
        userLoginForm.addEventListener("submit", function (event) {
            handleLogin(event, "user");
        });
    }

    if (adminLoginForm) {
        adminLoginForm.addEventListener("submit", function (event) {
            handleLogin(event, "admin");
        });
    }
});
