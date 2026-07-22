// Tab switching
const tabBtns = document.querySelectorAll(".tab-btn");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");

tabBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabBtns.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    if (btn.dataset.tab === "login") {
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");
    } else {
      registerForm.classList.remove("hidden");
      loginForm.classList.add("hidden");
    }
  });
});

// Login
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById("login-error");
  errorEl.textContent = "";

  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.detail || "Login failed";
      return;
    }

    localStorage.setItem("cybershield_token", data.access_token);
    localStorage.setItem("cybershield_user", data.username);
    window.location.href = "/dashboard.html";
  } catch (err) {
    errorEl.textContent = "Could not reach the server.";
  }
});

// Register
registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById("register-error");
  errorEl.textContent = "";

  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;

  try {
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.detail || "Registration failed";
      return;
    }

    localStorage.setItem("cybershield_token", data.access_token);
    localStorage.setItem("cybershield_user", data.username);
    window.location.href = "/dashboard.html";
  } catch (err) {
    errorEl.textContent = "Could not reach the server.";
  }
});
