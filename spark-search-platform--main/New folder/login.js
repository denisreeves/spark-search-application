document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("user-login-form");

  if (loginForm) {
      loginForm.addEventListener("submit", async function (event) {
          event.preventDefault();

          const username = document.getElementById("user-username").value.trim();
          const password = document.getElementById("user-password").value.trim();
          const errorMessage = document.getElementById("user-login-error");

          errorMessage.textContent = "";

          if (!username || !password) {
              errorMessage.textContent = "Username and password are required.";
              return;
          }

          try {
              const response = await fetch("/login", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ username, password }),
              });

              const data = await response.json();

              if (response.ok) {
                  window.location.href = "/dashboard";  // Redirect to user dashboard
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
