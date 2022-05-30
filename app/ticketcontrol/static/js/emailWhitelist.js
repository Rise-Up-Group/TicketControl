function removeEmailWhitelistEntry(button) {
    button.parentNode.remove();
}

function addEmailWhitelistEntry() {
    let div = document.createElement("div");
    let input = document.createElement("input");
    input.name = "register.email-whitelist";
    input.type = "email";
    input.placeholder = "@example.com";
    div.appendChild(input);
    div.innerHTML += " ";
    let button = document.createElement("a");
    button.innerHTML = "Löschen";
    button.classList.add("btn");
    button.classList.add("btn-primary");
    button.setAttribute("onclick", "removeEmailWhitelistEntry(this)");
    div.appendChild(button);
    let emailWhitelist = document.getElementById("register.email_whitelist");
    emailWhitelist.appendChild(div);
    emailWhitelist.lastChild.firstChild.focus();
    return false;
}