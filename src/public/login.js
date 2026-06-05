const debug = false;

const username_input = document.getElementById("username");
username_input.style.display = "none";

function onload() {
  if (debug) {
    console.log("DEBUG: onload loaded");
  }
  let cookies = document.cookie;

  fetch("/api/auth_cookies", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
    body: JSON.stringify({ cookies }),
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      if (debug) {
        console.log("DEBUG: respone get auth-cookies");
      }
      if (data.success) {
        window.location.href = "index.html";
      }
    });
}

function login() {
  if (debug) {
    console.log("DEBUG: function login loaded");
  }
  var email = document.getElementById("email").value;
  var password = document.getElementById("password").value;

  fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
    body: JSON.stringify({ email: email, passwd: password }),
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      if (debug) {
        console.log("DEBUG: respone get login");
      }
      if (data.success) {
        window.location.href = "index.html";
      } else {
        document.getElementById("warning").innerHTML =
          "<h4>Login failed, check for typos.</h4>";
      }
    })
    .catch((error) => {
      if (debug) {
        console.log("DEBUG: login api error");
      }
      document.getElementById("warning").innerHTML =
        "<h4>Server not reachable. Please try again later.</h4>";
    });
}

function register_redirect() {
  if (debug) {
    console.log("DEBUG: function register redirect loaded");
  }
  const login_button = document.getElementById("login");
  const main_button = document.getElementById("register_redirect");

  document.getElementById("ahaa").innerHTML =
    '<a onclick="gotologin()">Already have an account?</a>';

  main_button.textContent = "Register";
  main_button.setAttribute("onclick", "register()");
  main_button.className = "action-button";

  document.getElementById("landr").innerHTML = "<div>Register</div>";

  login_button.style.display = "none";
  username_input.style.display = "block";
}

function register() {
  if (debug) {
    console.log("DEBUG: function register loaded");
  }
  var username = document.getElementById("username").value;
  var email = document.getElementById("email").value;
  var password = document.getElementById("password").value;

  fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
    body: JSON.stringify({
      username: username,
      email: email,
      passwd: password,
    }),
  })
    .then((response) => response.json())
    .catch((error) => {
      document.getElementById("warning").innerHTML =
        "<h4>Server not reachable. Please try again later.</h4>";
    });
}

function gotologin() {
  const login_button = document.getElementById("login");
  const main_button = document.getElementById("register_redirect");

  document.getElementById("ahaa").innerHTML = "";

  main_button.textContent = "Register";
  main_button.setAttribute("onclick", "register_redirect()");
  main_button.className = "";

  document.getElementById("landr").innerHTML = "<div>Login</div>";

  login_button.style.display = "block";
  username_input.style.display = "none";
}
