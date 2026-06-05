function switchToChat() {
  document.getElementById("current-chat-name").innerText = "Testchat";
  document.getElementById("group-item").classList.remove("active");
  document.getElementById("chat-item").classList.add("active");
}

function switchToGroup() {
  document.getElementById("current-chat-name").innerText = "Testgruppe";
  document.getElementById("chat-item").classList.remove("active");
  document.getElementById("group-item").classList.add("active");
}

function checkLoginStatus() {
  fetch("/api/check-auth")
    .then((response) => response.json())
    .then((data) => {
      if (data.loggedIn) {
        console.log("");
      } else {
        showAlert("You are not logged in.");
      }
    })
    .catch((error) => {
      showAlert("Server not reachable. Please try again later.");
    });
}

function showAlert(message) {
  const alertBox = document.getElementById("alert");
  const alertText = document.getElementById("alert-text");
  alertText.innerText = message;
  alertBox.style.display = "block";
  setTimeout(closeAlert, 4000);
}

function closeAlert() {
  document.getElementById("alert").style.display = "none";
}

checkLoginStatus();
