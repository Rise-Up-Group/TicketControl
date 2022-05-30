function removeEmailWhitelistEntry(button) {
    button.parentNode.parentNode.remove();
}

function addEmailWhitelistEntry() {
    let div = document.createElement("div");
    let input = document.createElement("input");
    let buttonDiv = document.createElement("div");
    input.name = "register.email-whitelist";
    input.type = "text";
    input.classList.add("form-control");
    buttonDiv.classList.add("input-group-append");
    buttonDiv.classList.add("text-white");
    div.appendChild(input);
    div.innerHTML += " ";
    div.classList.add("input-group");
    div.classList.add("mb-3");
    let button = document.createElement("a");
    button.innerHTML = "Löschen";
    button.classList.add("btn");
    button.classList.add("btn-danger");
    button.setAttribute("onclick", "removeEmailWhitelistEntry(this)");
    buttonDiv.appendChild(button);
    div.appendChild(buttonDiv);
    let emailWhitelist = document.getElementById("register.email_whitelist");
    emailWhitelist.appendChild(div);
    emailWhitelist.lastChild.firstChild.focus();
    return false;
}