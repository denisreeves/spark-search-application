document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("admin-login-form");
  
    if (loginForm) {
      loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();
  
        const username = document.getElementById("admin-username").value.trim();
        const password = document.getElementById("admin-password").value.trim();
        const errorMessage = document.getElementById("admin-login-error");
  
        errorMessage.textContent = "";
  
        if (!username || !password) {
          errorMessage.textContent = "Username and password are required.";
          return;
        }
  
        try {
          const response = await fetch("/admin/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
          });
  
          const data = await response.json();
  
          if (response.ok) {
            console.log("✅ Debug: Redirecting to", data.redirect);
            window.location.href = data.redirect;  // ✅ Redirect to admin dashboard
          } else {
            errorMessage.textContent = data.message || "Invalid credentials.";
          }
        } catch (error) {
          console.error("Login request failed:", error);
          errorMessage.textContent = "An error occurred. Please try again.";
        }
      });
    }
  });
  