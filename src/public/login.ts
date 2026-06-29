export {};

const username_input = document.getElementById("username");
username_input!.style.display = "none";

function login() {
  var email = (document.getElementById("email") as HTMLInputElement).value;
  var password = (document.getElementById("password") as HTMLInputElement)
    .value;

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
        window.location.href = "index.html?login=true";
      } else {
        document.getElementById("warning")!.innerHTML =
          "<h4>Login failed, check your credentials.</h4>";
      }
    })
    .catch((error) => {
      document.getElementById("warning")!.innerHTML =
        "<h4>Server unreachable. Please try again later.</h4>";
    });
}

function register_redirect() {
  const login_button = document.getElementById("login") as HTMLInputElement;
  const main_button = document.getElementById(
    "register_redirect",
  ) as HTMLInputElement;

  document.getElementById("ahaa")!.innerHTML =
    '<a onclick="gotologin()">Already have an account?</a>';

  main_button.textContent = "Register";
  main_button.setAttribute("onclick", "register()");
  main_button.className = "action-button";

  document.getElementById("landr")!.innerHTML = "<div>Register</div>";

  login_button.style.display = "none";
  username_input!.style.display = "block";

  document.getElementById("tos-container")!.style.display = "flex";
  main_button.disabled = (
    document.getElementById("tos-checkbox") as HTMLInputElement
  ).checked;
}

function register() {
  var username = (document.getElementById("username") as HTMLInputElement)
    .value;
  var email = (document.getElementById("email") as HTMLInputElement).value;
  var password = (document.getElementById("password") as HTMLInputElement)
    .value;

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
        console.log("Account created");
        window.location.reload();
      }
    })
    .catch((error) => {
      document.getElementById("warning")!.innerHTML =
        "<h4>Server unreachable. Please try again later.</h4>";
    });
}

function gotologin() {
  const login_button = document.getElementById("login") as HTMLButtonElement;
  const main_button = document.getElementById(
    "register_redirect",
  ) as HTMLButtonElement;

  document.getElementById("ahaa")!.innerHTML = "";

  main_button.textContent = "Register";
  main_button.setAttribute("onclick", "register_redirect()");
  main_button.className = "";

  document.getElementById("landr")!.innerHTML = "<div>Login</div>";

  login_button.style.display = "block";
  username_input!.style.display = "none";

  document.getElementById("tos-container")!.style.display = "none";
  main_button.disabled = false;
}

function toggleRegisterButton() {
  const checkbox = document.getElementById("tos-checkbox") as HTMLInputElement;
  const registerBtn = document.getElementById(
    "register_redirect",
  ) as HTMLButtonElement;
  registerBtn.disabled = checkbox.checked;
}

function openToS() {
  document.getElementById("tos-modal")!.style.display = "flex";
}

function closeToS() {
  document.getElementById("tos-modal")!.style.display = "none";
}

window.onclick = function (event: MouseEvent) {
  const modal = document.getElementById("tos-modal");
  if (modal && event.target === modal) {
    modal.style.display = "none";
  }
};

function getCookie(name: string) {
  let matches = document.cookie.match(
    new RegExp(
      "(?:^|; )" +
        name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, "\\$1") +
        "=([^;]*)",
    ),
  );
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function applyTheme() {
  const isBright = getCookie("theme") === "bright";

  document.body.classList.toggle("bright-body", isBright);

  const loginBox = document.querySelector(".login");
  if (loginBox) loginBox.classList.toggle("bright-login", isBright);

  const landr = document.querySelector(".landr");
  if (landr) landr.classList.toggle("bright-landr", isBright);

  const loginF = document.querySelector(".login-f");
  if (loginF) loginF.classList.toggle("bright-login-f", isBright);

  const ahaa = document.querySelector("#ahaa");
  if (ahaa) ahaa.classList.toggle("bright-ahaa", isBright);

  const tosContainer = document.querySelector(".tos-container");
  if (tosContainer)
    tosContainer.classList.toggle("bright-tos-container", isBright);
}

function toggleTheme() {
  const currentTheme = getCookie("theme");
  const newTheme = currentTheme === "bright" ? "dark" : "bright";
  document.cookie = "theme=" + newTheme + "; path=/; max-age=31536000";
  applyTheme();
}

document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.createElement("button");
  toggleBtn.innerText = "🌓 Mode";
  toggleBtn.style.position = "absolute";
  toggleBtn.style.top = "10px";
  toggleBtn.style.right = "16px";
  toggleBtn.style.zIndex = "1000";
  toggleBtn.style.padding = "8px 14px";
  toggleBtn.style.borderRadius = "6px";
  toggleBtn.style.cursor = "pointer";
  toggleBtn.style.fontWeight = "600";
  toggleBtn.style.border = "1px solid #2f3b43";
  toggleBtn.style.backgroundColor = "#2a3942";
  toggleBtn.style.color = "#ffffff";

  toggleBtn.onclick = toggleTheme;
  document.body.appendChild(toggleBtn);

  applyTheme();
});
