function remove_email_whitelist_entry(button) {
    button.parentNode.parentNode.remove();
}

function add_email_whitelist_entry() {
    let div = document.createElement("div");
    let input = document.createElement("input");
    let button_div = document.createElement("div");
    input.name = "register.email-whitelist";
    input.type = "text";
    input.placeholder = "@example.com";
    input.classList.add("form-control");
    button_div.classList.add("input-group-append");
    button_div.classList.add("text-white");
    div.appendChild(input);
    div.innerHTML += " ";
    div.classList.add("input-group");
    div.classList.add("mb-3");
    let button = document.createElement("a");
    button.innerHTML = "Löschen";
    button.classList.add("btn");
    button.classList.add("btn-danger");
    button.setAttribute("onclick", "remove_email_whitelist_entry(this)");
    button_div.appendChild(button);
    div.appendChild(button_div);
    let email_whitelist = document.getElementById("register.email_whitelist");
    email_whitelist.appendChild(div);
    email_whitelist.lastChild.firstChild.focus();
    return false;
}

function show_email_whitelist() {
    let checkbox = document.getElementById("register.email-whitelist-enable");
    let whitelist = document.getElementById("email-whitelist");
    if (checkbox.checked) {
        whitelist.style.display = "block";
    } else {
        whitelist.style.display = "None";
    }
}

function add_textarea_open_listeners() {
    document.querySelectorAll("textarea").forEach(textarea => {
        textarea.addEventListener("focus", event => {
            event.target.rows = 25;
            event.target.parentNode.parentNode.scrollIntoView();
        });
        textarea.addEventListener("focusout", event => {
            event.target.rows = 5;
        });
    })
}

async function submit_form(form) {
    let form_data = new FormData(form);

    let action = "";
    if (form.hasAttribute("action")) action = form.getAttribute("action");
    else action = window.location.pathname;
    let method = "GET";
    if (form.hasAttribute("method")) method = form.getAttribute("method");
    window.scrollTo(0, 0);
    let res = await fetch(action, {
        method: method,
        body: form_data
    });
    if (res.status !== 200) {
        document.getElementById('response').contentWindow.document.write(await res.text());
        document.getElementById('response').style.display = "block";
        $("#response-modal").modal("show");
    }
}
