const username_input = document.getElementById("username");
username_input.style.display = "none";

function login() {
  var email = document.getElementById("email").value;
  var password = document.getElementById("password").value;

  fetch("/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ nameomail: email, passwd: password }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        window.location.href = "index.html";
      } else {
        document.getElementById("warning").innerHTML =
          "<h4>Login failed, check your credentials.</h4>";
      }
    })
    .catch((error) => {
      document.getElementById("warning").innerHTML =
        "<h4>Server unreachable. Please try again later.</h4>";
    });
}

function register_redirect() {
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

  document.getElementById("tos-container").style.display = "flex";
  main_button.disabled = !document.getElementById("tos-checkbox").checked;
}

function register() {
  var username = document.getElementById("username").value;
  var email = document.getElementById("email").value;
  var password = document.getElementById("password").value;

  fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      username: username,
      email: email,
      passwd: password,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        alert("Account Created");
        window.location.reload();
      }
    })
    .catch((error) => {
      document.getElementById("warning").innerHTML =
        "<h4>Server unreachable. Please try again later.</h4>";
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

  document.getElementById("tos-container").style.display = "none";
  main_button.disabled = false;
}

function toggleRegisterButton() {
  const checkbox = document.getElementById("tos-checkbox");
  const registerBtn = document.getElementById("register_redirect");
  registerBtn.disabled = !checkbox.checked;
}

function openToS() {
  document.getElementById("tos-modal").style.display = "flex";
}

function closeToS() {
  document.getElementById("tos-modal").style.display = "none";
}

window.onclick = function (event) {
  const modal = document.getElementById("tos-modal");
  if (event.target === modal) {
    modal.style.display = "none";
  }
};
