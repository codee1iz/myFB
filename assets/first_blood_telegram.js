(() => {
  const settings = window.firstBloodTelegramSettings || {};

  const elements = {
    alert: document.getElementById("fb-tg-alert"),
    enabled: document.getElementById("fb-tg-enabled"),
    token: document.getElementById("fb-tg-token"),
    tokenHelp: document.getElementById("fb-tg-token-help"),
    clearToken: document.getElementById("fb-tg-clear-token"),
    chatId: document.getElementById("fb-tg-chat-id"),
    parseMode: document.getElementById("fb-tg-parse-mode"),
    template: document.getElementById("fb-tg-template"),
    save: document.getElementById("fb-tg-save"),
    test: document.getElementById("fb-tg-test"),
  };

  let clearToken = false;
  let initial = { ...settings };

  const showAlert = (type, message) => {
    if (!elements.alert) {
      return;
    }
    elements.alert.innerHTML = `
      <div class="alert alert-${type} alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="close" data-dismiss="alert" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
    `;
  };

  const updateTokenHelp = () => {
    if (!elements.tokenHelp) {
      return;
    }
    if (clearToken) {
      elements.tokenHelp.textContent = "Token will be cleared on save.";
      return;
    }
    if (initial.token_is_set) {
      const masked = initial.token_masked ? ` (${initial.token_masked})` : "";
      elements.tokenHelp.textContent = `Token is set: yes${masked}`;
    } else {
      elements.tokenHelp.textContent = "Token is set: no";
    }
  };

  const populate = () => {
    elements.enabled.checked = Boolean(initial.enabled);
    elements.chatId.value = initial.chat_id || "";
    elements.parseMode.value = initial.parse_mode || "";
    elements.template.value = initial.template || "";
    updateTokenHelp();
  };

  const fetchSettings = async () => {
    const response = await fetch("/admin/first_blood_telegram/?format=json", {
      credentials: "same-origin",
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
      throw new Error(data.error || "Failed to fetch settings");
    }
    initial = data.settings;
    clearToken = false;
    elements.token.value = "";
    populate();
  };

  elements.clearToken.addEventListener("click", () => {
    clearToken = true;
    elements.token.value = "";
    updateTokenHelp();
  });

  elements.save.addEventListener("click", async () => {
    const payload = {};

    if (elements.enabled.checked !== Boolean(initial.enabled)) {
      payload.enabled = elements.enabled.checked;
    }

    const chatId = elements.chatId.value.trim();
    if (chatId !== (initial.chat_id || "")) {
      payload.chat_id = chatId;
    }

    const parseMode = elements.parseMode.value;
    if (parseMode !== (initial.parse_mode || "")) {
      payload.parse_mode = parseMode;
    }

    const template = elements.template.value.trim();
    if (template !== (initial.template || "")) {
      payload.template = template;
    }

    const token = elements.token.value.trim();
    if (clearToken) {
      payload.clear_token = true;
    } else if (token) {
      payload.token = token;
    }

    try {
      const response = await fetch("/admin/first_blood_telegram/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to save settings");
      }
      await fetchSettings();
      showAlert("success", "Settings saved successfully.");
    } catch (error) {
      showAlert("danger", error.message);
    }
  });

  elements.test.addEventListener("click", async () => {
    try {
      const response = await fetch("/admin/first_blood_telegram/test", {
        method: "POST",
        credentials: "same-origin",
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to send test message");
      }
      showAlert("success", "Test message sent.");
    } catch (error) {
      showAlert("danger", error.message);
    }
  });

  populate();
})();
