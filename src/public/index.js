const debug = true;

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

function openAddFriendsMenu() {
  if (debug) {
    console.log("DEBUG: opening addFriensMenu: ");
  }
  document.getElementById("add-chat-modal").classList.remove("modal-hidden");
}

function closeAddFriendsMenu() {
  if (debug) {
    console.log("DEBUG: closing addFriensMenu: ");
  }
  document.getElementById("add-chat-modal").classList.add("modal-hidden");
}

function confirmAddFriends() {
  if (debug) {
    console.log("DEBUG: adding Friend(s): ");
  }
  let friendsusernameinput = document.getElementById(
    "friends-username-input",
  ).value;
  fetch("/api/add_friends", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
    body: JSON.stringify({ cookies }),
    credentials: "include",
  })
    .then((response) => response.json())
    .then(() => onload())
    .catch((error) => {
      alert("user do not exists");
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
}

function closeAlert() {
  document.getElementById("alert").style.display = "none";
}

window.addEventListener("click", function (event) {
  const modal = document.getElementById("add-chat-modal");
  if (event.target === modal) {
    closeAddFriendsMenu();
  }
});

checkLoginStatus();
