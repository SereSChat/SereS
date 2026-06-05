const debug = false;

let chats = null;
let chats_count = null;

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
      if (!data.success) {
        window.location.href = "login.html";
      }
    })
    .catch((error) => {
      if (debug) {
        console.log("DEBUG: error onload");
      }
      showAlert("Server not reachable. Please try again later.");
      console.log(
        "Server not reachable. Please try again later. (cookie failed)",
      ); // only development
      // window.location.href = "login.html";
    })
    .catch((error) => {
      showAlert("Server not reachable. Please try again later.");
    });
  fetch("/api/load_chats", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
    body: JSON.stringify({ cookies }),
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      chats = data.chats;
      chatsCount = chats.length;

      let dmList = document.getElementById("dm-list");
      dmList.innerHTML = "";

      for (let i = 0; i < chats.length; i++) {
        let currentChat = chats[i];

        for (let name in currentChat) {
          let username = name;
          let lastMessage = currentChat[name];
          let chatHtml =
            '<div class="list-item" onclick="changeChat(\'' +
            username +
            "')\">" +
            '<div class="avatar" style="background-color: #5865f2">TC</div>' +
            '<div class="item-info">' +
            '<span class="item-name">' +
            username +
            "</span>" +
            '<span class="item-status">' +
            lastMessage +
            "</span>" +
            "</div>" +
            "</div>";

          dmList.innerHTML = dmList.innerHTML + chatHtml;
        }
      }
    });
}

function changeChat(name) {
  if (debug) {
    console.log("DEBUG: Chat changed: " + name);
  }
  document.getElementById("current-chat-name").innerText = name;

  let groupItem = document.getElementById("group-item");
  if (groupItem) {
    groupItem.classList.remove("active");
  }
}

function switchToChat() {
  if (debug) {
    console.log("DEBUG: chat switch");
  }
  document.getElementById("current-chat-name").innerText = "Testchat";
  document.getElementById("group-item").classList.remove("active");
  document.getElementById("chat-item").classList.add("active");
}

function switchToGroup() {
  if (debug) {
    console.log("DEBUG: group switch");
  }
  document.getElementById("current-chat-name").innerText = "Testgruppe";
  document.getElementById("chat-item").classList.remove("active");
  document.getElementById("group-item").classList.add("active");
}

function showAlert(message) {
  if (debug) {
    console.log("DEBUG: alert");
  }
  const alertBox = document.getElementById("alert");
  const alertText = document.getElementById("alert-text");
  alertText.innerText = message;
  alertBox.style.display = "block";
}
