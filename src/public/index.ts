(() => {
  const debug = true;

  let chats: any[] | null = null;
  let current_chat: any | null = null;
  let chats_count: number | null = null;
  let userImagePath = "";
  let currentChatId: string | null = null;
  let currentListView: "chats" | "requests" = "chats";
  const resolvedFriendRequests = new Set<string>(
    JSON.parse(sessionStorage.getItem("resolvedFriendRequests") || "[]"),
  );

  let refreshTimer: number | null = null;

  function page_load() {
    if (debug) {
      console.log("DEBUG: page_load loaded");
    }
    load_animation();
    load_chats();
    load_pending_requests();
    auth_cookie();
    load_avatar();
    load_username();
    initListViewButtons();
    attachPendingRequestListeners();

    if (window.innerWidth <= 768) {
      const sidebar = document.querySelector(".sidebar");
      if (sidebar) {
        sidebar.classList.add("open");
      }
    }

    if (refreshTimer !== null) {
      clearInterval(refreshTimer);
    }

    refreshTimer = window.setInterval(() => {
      if (currentListView === "requests") {
        load_pending_requests();
      } else {
        load_chats();
      }
      if (currentChatId) {
        load_messages();
      }
    }, 10000);
  }

  function load_animation() {
    const introLayer = document.getElementById("intro-layer");
    const introVideo = document.getElementById(
      "intro-video",
    ) as HTMLVideoElement | null;

    function removeOverlay() {
      if (introLayer) {
        introLayer.style.opacity = "0";
        setTimeout(() => {
          introLayer.remove();
        }, 500);
      }
    }

    const urlParams = new URLSearchParams(window.location.search);
    const isLoginRedirect = urlParams.get("login") === "true";
    const isFirstLoadOfSession =
      sessionStorage.getItem("sessionStarted") === null;

    if (isLoginRedirect) {
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);
      sessionStorage.setItem("sessionStarted", "true");
    } else if (isFirstLoadOfSession) {
      sessionStorage.setItem("sessionStarted", "true");
    } else {
      if (introLayer) introLayer.remove();
      return;
    }

    if (introVideo && introLayer) {
      introVideo.muted = true;
      introVideo.playsInline = true;

      const safetyTimeout = setTimeout(() => {
        removeOverlay();
      }, 5000);

      introVideo.play().catch((error) => {
        clearTimeout(safetyTimeout);
        if (introLayer) introLayer.remove();
      });

      introVideo.onended = () => {
        clearTimeout(safetyTimeout);
        setTimeout(() => {
          removeOverlay();
        }, 1000);
      };
    } else {
      if (introLayer) introLayer.remove();
    }
  }

  function logout() {
    fetch("/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    })
      .then((response) => response.json())
      .then((data) => {
        window.location.href = "login.html";
      });
  }

  function load_avatar() {
    const avatarText = document.getElementById("user-avatar-text");
    const avatarImg = document.getElementById(
      "user-avatar-img",
    ) as HTMLImageElement | null;
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
    const username = getCookie("username") || "";
    const usernameDisplay = document.getElementById("my-username-display");
    const currentChatName = document.getElementById("current-chat-name");
    const mobileUsername = document.getElementById("mobile-username");

    if (usernameDisplay) {
      usernameDisplay.innerText = username;
    }
    if (currentChatName) {
      currentChatName.innerText = "Welcome " + username;
    }
    if (mobileUsername) {
      mobileUsername.innerText = username;
    }
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
          console.log("DEBUG: error page_load");
        }
        showAlert("Server unreachable. Please try again later.");
        console.log(
          "Server not reachable. Please try again later. (cookie failed)",
        );
      });
  }

  function load_chats() {
    fetch("/api/load_chats", {
      method: "GET",
      credentials: "include",
    })
      .then((response) => response.json())
      .then((data) => {
        chats = data.chats;

        if (chats) {
          chats_count = chats.length;

          let dmList = document.getElementById("dm-list");
          if (!dmList) return;

          dmList.innerHTML = "";

          for (let i = 0; i < chats.length; i++) {
            let currentChat = chats[i];
            let chatId = currentChat.chat;

            if (debug) {
              console.log(
                "DEBUG: Loading chat with: " +
                  currentChat.other_user +
                  " (ID: " +
                  chatId +
                  ")",
              );
            }

            let chatHtml = `
              <div class="list-item" onclick="changeChat('${currentChat.other_user}', '${chatId}')">
                <div class="avatar" style="background-color: #5865f2">
                  ${currentChat.other_user.charAt(0).toUpperCase()}
                </div>
                <div class="item-info">
                  <span class="item-name">${currentChat.other_user}</span>
                  <span class="item-status">${currentChat.last_message || "No messages"}</span>
                </div>
                <button class="delete-chat-btn" type="button" onclick="remove_chat('${currentChat.other_user}', event)">×</button>
              </div>
            `;

            dmList.innerHTML = dmList.innerHTML + chatHtml;
          }
        }
      })
      .catch((err) => console.error("Error loading chats:", err));
  }

  function acceptFriendRequest(username: string, event?: Event) {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    if (debug) {
      console.log("DEBUG: accepting friend request for username:", username);
    }

    fetch("/api/add_friend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ friend_username: username }),
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) {
          throw new Error(data.message || "Error accepting friend request");
        }
      })
      .then(() =>
        fetch("/api/new_chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ friend_username: username }),
        }),
      )
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) {
          throw new Error(data.message || "Error creating new chat");
        }
      })
      .then(() => {
        resolvedFriendRequests.add(username);
        sessionStorage.setItem(
          "resolvedFriendRequests",
          JSON.stringify([...resolvedFriendRequests]),
        );
        load_pending_requests();
        load_chats();
      })
      .catch((error) => {
        console.error("Error accepting friend request or creating chat:", error);
      });
  }

  function discardFriendRequest(username: string, event?: Event) {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    if (debug) {
      console.log("DEBUG: discarding friend request for username:", username);
    }

    fetch("/api/discard_friend_request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ friend_username: username }),
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) {
          throw new Error(data.message || "Error discarding friend request");
        }
        return data;
      })
      .then(() => {
        load_pending_requests();
      })
      .catch((error) => {
        console.error("Error discarding friend request:", error);
      });

    const target =
      event instanceof Event ? (event.target as HTMLElement | null) : null;
    const requestItem = target?.closest(".list-item");
    if (requestItem) {
      requestItem.remove();
    }
  }

  function load_pending_requests() {
    fetch("/api/pending_friends", {
      method: "GET",
      credentials: "include",
    })
      .then((response) => response.json())
      .then((data) => {
        const requestsList = document.getElementById("requests-list");
        if (!requestsList) return;

        requestsList.innerHTML = "";

        const pendingFriends = (data.pending_friends || []).filter(
          (username: string) => !resolvedFriendRequests.has(username),
        );
        if (!pendingFriends.length) {
          requestsList.innerHTML = `
            <div class="list-item request-list-item">
              <div class="avatar" style="background-color: #5865f2">!</div>
              <div class="item-info">
                <span class="item-name">No pending requests</span>
                <span class="item-status">Friend requests you received will show here.</span>
              </div>
            </div>
          `;
          return;
        }

        pendingFriends.forEach((username: string) => {
          requestsList.innerHTML += `
            <div class="list-item request-list-item">
              <div class="avatar" style="background-color: #00a884">${username.charAt(0).toUpperCase()}</div>
              <div class="item-info">
                <span class="item-name">${username}</span>
                <span class="item-status">Pending friend request</span>
              </div>
              <div class="request-actions">
                <button class="request-action-btn accept" type="button" data-action="accept" data-username="${username}">Accept</button>
                <button class="request-action-btn discard" type="button" data-action="discard" data-username="${username}">Discard</button>
              </div>
            </div>
          `;
        });
      })
      .catch((err) => console.error("Error loading pending requests:", err));
  }

  function switchListViewr() {
    currentListView = "requests";
    const directMessagesHeader = document.getElementById("direct-messages");
    const panels = document.querySelectorAll<HTMLElement>(".list-view-panel");
    const buttons = document.querySelectorAll<HTMLElement>(".list-view-toggle");

    buttons.forEach((button) => {
      button.classList.toggle("active", button.id === "requests-toggle");
    });

    panels.forEach((panel) => {
      panel.classList.toggle("active", panel.id === "requests-list");
    });

    if (directMessagesHeader) {
      directMessagesHeader.style.display = "none";
    }
  }

  function switchListViewc() {
    currentListView = "chats";
    const directMessagesHeader = document.getElementById("direct-messages");
    const panels = document.querySelectorAll<HTMLElement>(".list-view-panel");
    const buttons = document.querySelectorAll<HTMLElement>(".list-view-toggle");

    buttons.forEach((button) => {
      button.classList.toggle("active", button.id === "chats-toggle");
    });

    panels.forEach((panel) => {
      panel.classList.toggle("active", panel.id === "dm-list");
    });

    if (directMessagesHeader) {
      directMessagesHeader.style.display = "block";
    }
  }

  function initListViewButtons() {
    const requestsButton = document.getElementById("requests-toggle");
    const chatsButton = document.getElementById("chats-toggle");

    requestsButton?.addEventListener("click", switchListViewr);
    chatsButton?.addEventListener("click", switchListViewc);
  }

  function attachPendingRequestListeners() {
    const requestsList = document.getElementById("requests-list");
    if (!requestsList) return;

    requestsList.addEventListener("click", (event) => {
      const target = event.target;
      const element = target instanceof HTMLElement ? target : null;
      const button = element?.closest<HTMLButtonElement>(
        "button.request-action-btn",
      );
      if (!button) return;

      const username = button.dataset.username;
      const action = button.dataset.action;
      if (!username || !action) return;

      if (action === "accept") {
        acceptFriendRequest(username, event);
      } else if (action === "discard") {
        discardFriendRequest(username, event);
      }
    });
  }

  function remove_chat(username: string, event: any) {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    setTimeout(() => {
      if (
        !window.confirm(
          "Do you really want to delete the chat with " + username + "?",
        )
      ) {
        return;
      }

      fetch("/api/remove_chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username }),
        credentials: "include",
      })
        .then((response) => response.json())
        .then((data) => {
          if (data.success) {
            const currentChatNameElem =
              document.getElementById("current-chat-name");

            if (
              currentChatNameElem &&
              currentChatNameElem.innerText === username
            ) {
              currentChatNameElem.innerText =
                "Welcome " + (getCookie("username") || "");

              const chatInputArea = document.getElementById("chat-input-area");
              if (chatInputArea) {
                chatInputArea.classList.add("modal-hidden");
              }

              const messagesContainer = document.querySelector(
                ".messages-container",
              );
              if (messagesContainer) {
                messagesContainer.innerHTML = "";
              }
            }

            load_chats();
          } else {
            alert("Error deleting chat: " + (data.message || "Unknown error"));
          }
        })
        .catch((error) => {
          showAlert("Server unreachable. Chat could not be deleted.");
        });
    }, 10);
  }

  function toggleUserMenu() {
    const dropdown = document.getElementById("user-dropdown-menu");
    if (dropdown) {
      dropdown.classList.toggle("modal-hidden");
    }
  }

  window.addEventListener("click", function (event: MouseEvent) {
    const trigger = document.querySelector(".user-menu-trigger");
    const dropdown = document.getElementById("user-dropdown-menu");
    const modalAddFriend = document.getElementById("add-chat-modal");
    const modalSettings = document.getElementById("settings-modal");

    if (
      trigger &&
      !trigger.contains(event.target as Node) &&
      dropdown &&
      !dropdown.contains(event.target as Node)
    ) {
      dropdown.classList.add("modal-hidden");
    }

    if (event.target === modalAddFriend) {
      closeAddFriendMenu();
    }

    if (event.target === modalSettings) {
      closeSettingsMenu();
    }
  });

  function openSettings() {
    if (debug) {
      console.log("DEBUG: opening settingsMenu");
    }
    const modal = document.getElementById("settings-modal");
    if (modal) {
      modal.classList.remove("modal-hidden");
    }
  }

  function saveSettings() {
    if (debug) {
      console.log("DEBUG: saving settings and uploading avatar");
    }

    const fileInput = document.getElementById(
      "avatar-upload-input",
    ) as HTMLInputElement | null;
    const warningText = document.getElementById("settings-warning");

    if (warningText) warningText.innerText = "";

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
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
    formData.append("avatar_img", file);

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
          page_load();
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

    const uploadInput = document.getElementById(
      "avatar-upload-input",
    ) as HTMLInputElement | null;
    if (uploadInput) {
      uploadInput.value = "";
    }

    const warningText = document.getElementById("settings-warning");
    if (warningText) warningText.innerText = "";

    const modal = document.getElementById("settings-modal");
    if (modal) {
      modal.classList.add("modal-hidden");
    }
  }

  function openAddFriendMenu() {
    if (debug) {
      console.log("DEBUG: opening addFriensMenu: ");
    }
    const modal = document.getElementById("add-friend-modal");
    if (modal) {
      modal.classList.remove("modal-hidden");
    }
  }

  function closeAddFriendMenu() {
    if (debug) {
      console.log("DEBUG: closing addFriensMenu: ");
    }
    const modal = document.getElementById("add-friend-modal");
    if (modal) {
      modal.classList.add("modal-hidden");
    }
  }

  function requestAddFriend(friendUsername: string, sourceModal = false) {
    const trimmedUsername = friendUsername.trim();
    if (!trimmedUsername) return;

    const warningElem = document.getElementById("warning-add-friend");
    if (warningElem) warningElem.innerHTML = "";

    fetch("/api/add_friend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        friend_username: trimmedUsername,
      }),
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.message || "Error adding friend");
        }
        return data;
      })
      .then((data) => {
        if (debug) {
          console.log("DEBUG: Friend added, waiting for acceptance...");
        }
        if (sourceModal) {
          closeAddFriendMenu();
        }
        load_pending_requests();
      })
      .catch((error) => {
        console.error("Error in friend/chat creation workflow:", error);
        if (warningElem) {
          warningElem.innerHTML = error.message;
        }
      });
  }

  function promptAddFriend() {
    const friendUsername = window.prompt(
      "Enter the username of the friend to add:",
    );
    if (!friendUsername) return;
    requestAddFriend(friendUsername, false);
  }

  function confirmAddFriend() {
    if (debug) {
      console.log("DEBUG: adding Friend(s): ");
    }

    const inputElem = document.getElementById(
      "friends-username-input",
    ) as HTMLInputElement | null;
    if (!inputElem) return;

    requestAddFriend(inputElem.value, true);
  }

  function opennewchatsMenu() {
    if (debug) {
      console.log("DEBUG: opening newchatsMenu: ");
    }
    const modal = document.getElementById("add-chat-modal");
    if (modal) {
      modal.classList.remove("modal-hidden");
    }
  }

  function closenewchatsMenu() {
    if (debug) {
      console.log("DEBUG: closing newchatsMenu: ");
    }
    const modal = document.getElementById("add-chat-modal");
    if (modal) {
      modal.classList.add("modal-hidden");
    }
  }

  function confirnewchats() {
    if (debug) {
      console.log("DEBUG: creating new chat");
    }

    const inputElem = document.getElementById(
      "new-chat-username-input",
    ) as HTMLInputElement | null;
    if (!inputElem) return;

    const newchatusernameinput = inputElem.value.trim();
    if (!newchatusernameinput) return;

    const warningElem = document.getElementById("warning-new-chat");
    if (warningElem) warningElem.innerHTML = "";

    fetch("/api/new_chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        friend_username: newchatusernameinput,
      }),
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (data.message && data.message.includes("not your friend")) {
            requestAddFriend(newchatusernameinput, false);
            throw new Error(
              "This user is not your friend yet. A friend request was sent instead.",
            );
          }
          throw new Error(data.message || "Error creating chat");
        }
        return data;
      })
      .then(() => {
        closenewchatsMenu();
        load_chats();
      })
      .catch((error) => {
        if (warningElem) {
          warningElem.innerHTML =
            "<h4>This Chat already exists or an error occurred</h4>";
        }
        console.error("Error in chat creation workflow:", error);
      });
  }

  function changeChat(name: string, id: string) {
    if (debug) {
      console.log("DEBUG: Chat changed: " + name + " (ID: " + id + ")");
    }

    currentChatId = id;
    const chatNameElem = document.getElementById("current-chat-name");
    if (chatNameElem) {
      chatNameElem.innerText = name;
    }

    let inputArea = document.getElementById("chat-input-area");
    if (inputArea) {
      inputArea.classList.remove("modal-hidden");
    }

    let groupItem = document.getElementById("group-item");
    if (groupItem) {
      groupItem.classList.remove("active");
    }

    load_messages(name);
    load_messages(name, true);

    if (window.innerWidth <= 768) {
      const sidebar = document.querySelector(".sidebar");
      if (sidebar) {
        sidebar.classList.remove("open");
      }
    }
  }

  function switchToChat() {
    if (debug) {
      console.log("DEBUG: switched to chat");
    }
    const chatNameElem = document.getElementById("current-chat-name");
    if (chatNameElem) chatNameElem.innerText = "Testchat";

    const groupItemElem = document.getElementById("group-item");
    if (groupItemElem) groupItemElem.classList.remove("active");

    const chatItemElem = document.getElementById("chat-item");
    if (chatItemElem) chatItemElem.classList.add("active");
  }

  function showAlert(message: string) {
    if (debug) {
      console.log("DEBUG: Alert shown");
    }
    const alertBox = document.getElementById("alert");
    const alertText = document.getElementById("alert-text");

    if (alertText) alertText.innerText = message;
    if (alertBox) {
      alertBox.classList.remove("hidden");
      alertBox.style.display = "block";
    }

    setTimeout(() => {
      if (alertBox) {
        alertBox.classList.add("hidden");
        setTimeout(() => {
          alertBox.style.display = "none";
        }, 500);
      }
    }, 4000);
  }

  function getCookie(name: string) {
    if (debug) {
      console.log("DEBUG: load cookies");
    }
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

    const sidebar = document.querySelector(".sidebar");
    if (sidebar) sidebar.classList.toggle("bright-sidebar", isBright);

    const sidebarHeader = document.querySelector(".sidebar-header");
    if (sidebarHeader)
      sidebarHeader.classList.toggle("bright-sidebar-header", isBright);

    const mainChat = document.querySelector(".main-chat");
    if (mainChat) mainChat.classList.toggle("bright-main-chat", isBright);

    const chatHeader = document.querySelector(".chat-header");
    if (chatHeader) chatHeader.classList.toggle("bright-chat-header", isBright);

    const inputContainer = document.querySelector(".input-container");
    if (inputContainer)
      inputContainer.classList.toggle("bright-input-container", isBright);

    const inputBox = document.querySelector(".input-box");
    if (inputBox) inputBox.classList.toggle("bright-input-box", isBright);

    const userMenuContainer = document.querySelector(".user-menu-container");
    if (userMenuContainer)
      userMenuContainer.classList.toggle(
        "bright-user-menu-container",
        isBright,
      );

    const userDropdown = document.querySelector(".user-dropdown");
    if (userDropdown)
      userDropdown.classList.toggle("bright-user-dropdown", isBright);

    const dropdownUsername = document.querySelector(".dropdown-username");
    if (dropdownUsername)
      dropdownUsername.classList.toggle("bright-dropdown-username", isBright);

    const addChatBtn = document.querySelector(".add-chat-main-button");
    if (addChatBtn)
      addChatBtn.classList.toggle("bright-add-chat-main-button", isBright);

    document
      .querySelectorAll(".section-title")
      .forEach((el) => el.classList.toggle("bright-section-title", isBright));
    document
      .querySelectorAll(".list-item")
      .forEach((el) => el.classList.toggle("bright-list-item", isBright));
    document
      .querySelectorAll(".item-name")
      .forEach((el) => el.classList.toggle("bright-item-name", isBright));
    document
      .querySelectorAll(".item-status")
      .forEach((el) => el.classList.toggle("bright-item-status", isBright));
    document
      .querySelectorAll(".dropdown-divider")
      .forEach((el) =>
        el.classList.toggle("bright-dropdown-divider", isBright),
      );
    document
      .querySelectorAll(".dropdown-item")
      .forEach((el) => el.classList.toggle("bright-dropdown-item", isBright));
    document
      .querySelectorAll(".modal-overlay")
      .forEach((el) => el.classList.toggle("bright-modal-overlay", isBright));
    document
      .querySelectorAll(".modal-box")
      .forEach((el) => el.classList.toggle("bright-modal-box", isBright));
    document
      .querySelectorAll(".cancel-btn")
      .forEach((el) => el.classList.toggle("bright-cancel-btn", isBright));
    document
      .querySelectorAll(".modal")
      .forEach((el) => el.classList.toggle("bright-modal", isBright));
    document
      .querySelectorAll(".modal-content")
      .forEach((el) => el.classList.toggle("bright-modal-content", isBright));
  }

  function toggleTheme() {
    if (debug) {
      console.log("DEBUG: theme toggled");
    }
    const currentTheme = getCookie("theme");
    const newTheme = currentTheme === "bright" ? "dark" : "bright";
    document.cookie = "theme=" + newTheme + "; path=/; max-age=31536000";
    applyTheme();
  }

  function addThemeOptionToSettings() {
    const modalBox = document.querySelector("#settings-modal .modal-box");
    if (modalBox) {
      const themeSection = document.createElement("div");
      themeSection.style.marginTop = "15px";
      themeSection.style.borderTop = "1px solid #2f3b43";
      themeSection.style.paddingTop = "15px";

      const label = document.createElement("p");
      label.innerText = "App Design:";
      themeSection.appendChild(label);

      const themeBtn = document.createElement("button");
      themeBtn.type = "button";
      themeBtn.innerText = "🌓 Switch Light/Dark Mode";
      themeBtn.style.width = "100%";
      themeBtn.style.padding = "10px";
      themeBtn.style.borderRadius = "8px";
      themeBtn.style.cursor = "pointer";
      themeBtn.style.fontWeight = "bold";
      themeBtn.style.border = "1px solid #2f3b43";
      themeBtn.style.backgroundColor = "#2a3942";
      themeBtn.style.color = "#ffffff";

      themeBtn.onclick = toggleTheme;

      themeSection.appendChild(themeBtn);

      const buttonsDiv = modalBox.querySelector(".modal-buttons");
      if (buttonsDiv) {
        modalBox.insertBefore(themeSection, buttonsDiv);
      }
    }
  }

  window.addEventListener("DOMContentLoaded", () => {
    applyTheme();
    addThemeOptionToSettings();
  });

  function load_messages(name?: string, shouldScroll: boolean = false) {
    if (debug) {
      console.log("DEBUG: messages loading ...");
    }

    if (
      !currentChatId ||
      currentChatId === "undefined" ||
      currentChatId.trim() === ""
    ) {
      if (debug) {
        console.log("DEBUG: no valid currentChatId.");
      }
      return;
    }

    fetch("/api/get_messages?chat_id=" + encodeURIComponent(currentChatId), {
      method: "GET",
      credentials: "include",
    })
      .then((response) => response.json())
      .then((data) => {
        if (debug) {
          console.log("DEBUG: messages loaded");
        }
        let messagesContainer = document.querySelector(".messages-container");
        if (!messagesContainer) return;

        messagesContainer.innerHTML = "";

        const myUsername = getCookie("username");

        if (data.messages && data.messages.length > 0) {
          data.messages.forEach(
            (msg: { sender: string; content: string; timestamp: string }) => {
              let messageElement = document.createElement("div");
              messageElement.className = "message-row";

              if (msg.sender === myUsername) {
                messageElement.classList.add("message-own");
              }

              let avatar = document.createElement("div");
              avatar.className = "message-avatar";
              avatar.innerText = msg.sender.charAt(0).toUpperCase();

              let contentWrapper = document.createElement("div");
              contentWrapper.className = "message-content-wrapper";

              let header = document.createElement("div");
              header.className = "message-header";

              let senderSpan = document.createElement("span");
              senderSpan.className = "message-sender";
              senderSpan.innerText = msg.sender;

              let timeSpan = document.createElement("span");
              timeSpan.className = "message-timestamp";
              timeSpan.innerText = msg.timestamp || "Loading ...";

              header.appendChild(senderSpan);
              header.appendChild(timeSpan);

              let textDiv = document.createElement("div");
              textDiv.className = "message-text";
              textDiv.innerText = msg.content;

              contentWrapper.appendChild(header);
              contentWrapper.appendChild(textDiv);

              messageElement.appendChild(avatar);
              messageElement.appendChild(contentWrapper);

              messagesContainer!.appendChild(messageElement);
            },
          );

          if (shouldScroll) {
            scrollToBottom();
          }
        }
      })
      .catch((err) => console.error("Error loading messages:", err));
  }

  function send_message() {
    if (debug) {
      console.log("DEBUG: function send_message");
    }
    const inputElement = document.getElementById(
      "message-input-field",
    ) as HTMLInputElement | null;
    if (!inputElement) return;

    const messageText = inputElement.value.trim();
    const chatNameElem = document.getElementById("current-chat-name");
    const currentChatName = chatNameElem ? chatNameElem.innerText : "";

    if (!messageText || !currentChatId) return;

    fetch("/api/send_message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        chat_id: currentChatId,
        content: messageText,
      }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          inputElement.value = "";
          load_messages(currentChatName);
          load_messages(currentChatName, true);
          if (debug) {
            console.log("DEBUG: message sent");
          }
        } else {
          showAlert("Error sending message");
          load_messages(currentChatName, true);
          if (debug) {
            console.log("DEBUG: error while sending message");
          }
        }
      })
      .catch((error) => {
        showAlert("Server unreachable.");
      });
  }

  function toggleSidebar() {
    const sidebar = document.querySelector(".sidebar");
    if (sidebar) {
      sidebar.classList.toggle("open");
    }
  }

  document.addEventListener("click", (event) => {
    const sidebar = document.querySelector(".sidebar");
    const toggleBtn = document.querySelector(".menu-toggle");
    const target = event.target as Element;

    const isModalClick =
      target.closest(".modal-overlay") !== null ||
      target.classList.contains("modal-overlay");

    if (
      sidebar &&
      sidebar.classList.contains("open") &&
      window.innerWidth <= 768
    ) {
      if (
        !sidebar.contains(target) &&
        toggleBtn &&
        !toggleBtn.contains(target) &&
        !isModalClick
      ) {
        sidebar.classList.remove("open");
      }
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    const modals = ["add-friend-modal", "add-chat-modal", "settings-modal"];
    modals.forEach((id) => {
      const modal = document.getElementById(id);
      if (modal) {
        document.body.appendChild(modal);
      }
    });
  });

  function scrollToBottom(): void {
    setTimeout(() => {
      const messageContainer = document.querySelector(".messages-container");
      if (messageContainer) {
        messageContainer.scrollTop = messageContainer.scrollHeight;
      }
    }, 50);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const messageInput = document.getElementById(
      "message-input-field",
    ) as HTMLInputElement;

    if (messageInput) {
      messageInput.addEventListener("keydown", (event: KeyboardEvent) => {
        if (event.key === "Enter" && !event.shiftKey) {
          event.preventDefault();
          send_message();
        }
      });
    }
  });

  (window as any).toggleSidebar = toggleSidebar;
  (window as any).switchListViewr = switchListViewr;
  (window as any).switchListViewc = switchListViewc;
  (window as any).acceptFriendRequest = acceptFriendRequest;
  (window as any).discardFriendRequest = discardFriendRequest;
  (window as any).page_load = page_load;
  (window as any).logout = logout;
  (window as any).remove_chat = remove_chat;
  (window as any).toggleUserMenu = toggleUserMenu;
  (window as any).openSettings = openSettings;
  (window as any).saveSettings = saveSettings;
  (window as any).closeSettingsMenu = closeSettingsMenu;
  (window as any).openAddFriendMenu = openAddFriendMenu;
  (window as any).closeAddFriendMenu = closeAddFriendMenu;
  (window as any).confirmAddFriend = confirmAddFriend;
  (window as any).requestAddFriend = requestAddFriend;
  (window as any).promptAddFriend = promptAddFriend;
  (window as any).opennewchatsMenu = opennewchatsMenu;
  (window as any).closenewchatsMenu = closenewchatsMenu;
  (window as any).confirnewchats = confirnewchats;
  (window as any).changeChat = changeChat;
  (window as any).switchToChat = switchToChat;
  (window as any).send_message = send_message;
})();
