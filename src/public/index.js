const debug = true;

let chats = null;
let chats_count = null;
let userImagePath = "";

function onload() {
  if (debug) {
    console.log("DEBUG: onload loaded");
  }
  load_chats();
  auth_cookie();
  load_avatar();
  load_username();
}

function load_avatar() {
  const avatarText = document.getElementById("user-avatar-text");
  const avatarImg = document.getElementById("user-avatar-img");
  const username = getCookie("username");

  if (avatarText && avatarImg) {
    fetch("/api/get_avatar", {
      method: "GET",
      credentials: "include",
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("No avatar found");
        }
        return response.blob();
      })
      .then((imageBlob) => {
        userImagePath = URL.createObjectURL(imageBlob);
        avatarImg.src = userImagePath;
        avatarImg.style.display = "block";
        avatarText.style.display = "none";
      })
      .catch((error) => {
        if (username) {
          avatarText.innerText = username.charAt(0).toUpperCase();
        } else {
          avatarText.innerText = "?";
        }
        avatarText.style.display = "block";
        avatarImg.style.display = "none";
      });
  } else {
    console.log(
      "WARNING: 'user-avatar-text' or 'user-avatar-img' was not found in the HTML!",
    );
  }
}

function load_username() {
  const username = getCookie("username");
  document.getElementById("my-username-display").innerText = username;
  document.getElementById("current-chat-name").innerText =
    "Welcome " + username;
}

function auth_cookie() {
  fetch("/api/auth_cookie", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
      showAlert("Server unreachable. Please try again later.");
      console.log(
        "Server not reachable. Please try again later. (cookie failed)",
      ); // only development
      // window.location.href = "login.html";
    })
    .catch((error) => {
      showAlert("Server unreachable. Please try again later.");
    });
}

function load_chats() {
  fetch("/api/load_chats", {
    method: "POST",
    headers: { "Content-Type": "application.json" },
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

function toggleUserMenu() {
  const dropdown = document.getElementById("user-dropdown-menu");
  dropdown.classList.toggle("modal-hidden");
}

window.addEventListener("click", function (event) {
  const trigger = document.querySelector(".user-menu-trigger");
  const dropdown = document.getElementById("user-dropdown-menu");

  if (
    trigger &&
    !trigger.contains(event.target) &&
    dropdown &&
    !dropdown.contains(event.target)
  ) {
    dropdown.classList.add("modal-hidden");
  }
});

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop().split(";").shift();
  }
  return undefined;
}

function openSettings() {
  if (debug) {
    console.log("DEBUG: opening settingsMenu");
  }
  document.getElementById("settings-modal").classList.remove("modal-hidden");
}

function saveSettings() {
  if (debug) {
    console.log("DEBUG: saving settings and uploading avatar");
  }

  const fileInput = document.getElementById("avatar-upload-input");
  const warningText = document.getElementById("settings-warning");

  if (warningText) warningText.innerText = "";

  if (fileInput.files.length === 0) {
    closeSettingsMenu();
    return;
  }

  const file = fileInput.files[0];
  const maxSizeBytes = 1 * 1024 * 1024;

  if (file.size > maxSizeBytes) {
    if (warningText) {
      warningText.innerText = "File is too large! Maximum size is 1MB.";
    }
    return;
  }

  const formData = new FormData();
  formData.append("avatar", file);

  fetch("/api/upload_avatar", {
    method: "POST",
    body: formData,
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        alert("Avatar updated successfully!");
        closeSettingsMenu();
        onload();
      } else {
        if (warningText)
          warningText.innerText = "Upload failed: " + data.message;
      }
    })
    .catch((error) => {
      if (debug) console.log("DEBUG: Error uploading avatar", error);
      if (warningText)
        warningText.innerText = "Server error. Please try again later.";
    });
}

function closeSettingsMenu() {
  if (debug) {
    console.log("DEBUG: closing settingsMenu");
  }

  document.getElementById("avatar-upload-input").value = "";
  const warningText = document.getElementById("settings-warning");
  if (warningText) warningText.innerText = "";

  document.getElementById("settings-modal").classList.add("modal-hidden");
}

function logout() {
  document.cookie = "username=; max-age=1; path=/;";
  document.cookie = "sessioncookie=; max-age=1; path=/;";
  window.location.href = "login.html";
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
    credentials: "include",
  })
    .then((response) => response.json())
    .then(() => onload())
    .catch((error) => {
      document.getElementById("warning").innerHTML =
        "<h4>This username does not exist or is already in your friends list.</h4>";
    });
}

function changeChat(name) {
  if (debug) {
    console.log("DEBUG: Chat changed: " + name);
  }
  document.getElementById("current-chat-name").innerText = name;

  let inputArea = document.getElementById("chat-input-area");
  if (inputArea) {
    inputArea.classList.remove("modal-hidden");
  }

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

window.addEventListener("click", function (event) {
  const trigger = document.querySelector(".user-menu-trigger");
  const dropdown = document.getElementById("user-dropdown-menu");
  const modal = document.getElementById("add-chat-modal");

  if (
    trigger &&
    !trigger.contains(event.target) &&
    dropdown &&
    !dropdown.contains(event.target)
  ) {
    dropdown.classList.add("modal-hidden");
  }

  if (event.target === modal) {
    closeAddFriendsMenu();
  }
});

window.addEventListener("click", function (event) {
  const trigger = document.querySelector(".user-menu-trigger");
  const dropdown = document.getElementById("user-dropdown-menu");
  const modalAddFriend = document.getElementById("add-chat-modal");
  const modalSettings = document.getElementById("settings-modal");

  if (
    trigger &&
    !trigger.contains(event.target) &&
    dropdown &&
    !dropdown.contains(event.target)
  ) {
    dropdown.classList.add("modal-hidden");
  }

  if (event.target === modalAddFriend) {
    closeAddFriendsMenu();
  }

  if (event.target === modalSettings) {
    closeSettingsMenu();
  }
});
